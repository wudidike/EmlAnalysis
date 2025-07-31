import email
import email.policy
import re
import base64
import os
import quopri
from io import BytesIO
from PIL import Image
import pyzbar.pyzbar as pyzbar
from urllib.parse import urlparse, unquote
import html
import csv
from datetime import datetime
import sys
import hashlib
import textwrap

class 恶意邮件分析器:
    def __init__(self, eml文件路径):
        self.eml文件路径 = eml文件路径
        self.解析后的邮件 = None
        self.分析结果 = {
            '邮件头信息': {},
            '发件人路由': [],
            '收件人列表': {'收件人': [], '抄送': [], '密送': []},
            'URL信息': [],
            '附件信息': [],
            '二维码信息': [],
            '正文内容': {'文本': '', 'HTML': ''},
            '内容统计': {'文本字符数': 0, 'HTML字符数': 0}
        }
        
    def 解析邮件(self):
        """解析 EML 文件"""
        with open(self.eml文件路径, 'rb') as 文件:
            self.解析后的邮件 = email.message_from_binary_file(文件, policy=email.policy.default)
    
    def 提取邮件头信息(self):
        """提取邮件头信息"""
        关键头信息 = ['From', 'To', 'Subject', 'Date', 'Message-ID', 
                  'Return-Path', 'Reply-To', 'DKIM-Signature', 
                  'Received-SPF', 'X-Mailer', 'Content-Type']
        
        for 头字段 in 关键头信息:
            值 = self.解析后的邮件.get(头字段, '')
            if 值:
                self.分析结果['邮件头信息'][头字段] = 值
    
    def 提取发件人路由(self):
        """提取发件人路由路径"""
        接收头列表 = self.解析后的邮件.get_all('Received', [])
        for 接收头 in 接收头列表:
            # 清理并解析 Received 头
            清理后的接收头 = re.sub(r'\s+', ' ', 接收头).strip()
            self.分析结果['发件人路由'].append(清理后的接收头)
    
    def 提取收件人列表(self):
        """提取收件人列表"""
        # 提取收件人
        收件人头字段 = self.解析后的邮件.get('To', '')
        if 收件人头字段:
            self.分析结果['收件人列表']['收件人'] = self._解析邮件地址(收件人头字段)
        
        # 提取抄送
        抄送头字段 = self.解析后的邮件.get('Cc', '')
        if 抄送头字段:
            self.分析结果['收件人列表']['抄送'] = self._解析邮件地址(抄送头字段)
        
        # 提取密送
        密送头字段 = self.解析后的邮件.get('Bcc', '')
        if 密送头字段:
            self.分析结果['收件人列表']['密送'] = self._解析邮件地址(密送头字段)
    
    def _解析邮件地址(self, 地址头字段):
        """解析邮件地址"""
        地址列表 = []
        # 处理带编码的地址
        解码后的头字段 = email.header.decode_header(地址头字段)
        for 部分, 编码 in 解码后的头字段:
            if isinstance(部分, bytes):
                try:
                    编码 = 编码 if 编码 else 'utf-8'
                    部分 = 部分.decode(编码, errors='replace')
                except:
                    try:
                        部分 = 部分.decode('latin-1', errors='replace')
                    except:
                        部分 = str(部分)
            地址列表.append(str(部分))
        
        # 将列表合并为字符串后再分割
        合并地址 = ', '.join(地址列表)
        return [地址.strip() for 地址 in re.split(r'[,;]', 合并地址) if 地址.strip()]
    
    def 提取URL信息(self):
        """提取邮件中的所有 URL"""
        # 从文本正文提取
        文本正文 = self.分析结果['正文内容']['文本']
        self._从文本提取URL(文本正文)
        
        # 从 HTML 正文提取
        HTML正文 = self.分析结果['正文内容']['HTML']
        self._从HTML提取URL(HTML正文)
        
        # 从邮件头提取
        头字段列表 = self.解析后的邮件.items()
        for 头字段, 值 in 头字段列表:
            if isinstance(值, str) and 'http' in 值:
                self._从文本提取URL(值)
    
    def _从文本提取URL(self, 文本):
        """从文本中提取 URL"""
        if not 文本:
            return
            
        URL模式 = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        URL列表 = re.findall(URL模式, 文本)
        for URL in URL列表:
            self._添加URL(URL)
    
    def _从HTML提取URL(self, HTML内容):
        """从 HTML 中提取 URL"""
        if not HTML内容:
            return
            
        # 提取 <a> 标签链接
        a标签模式 = r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"'
        URL列表 = re.findall(a标签模式, HTML内容, re.IGNORECASE)
        for URL in URL列表:
            self._添加URL(URL)
        
        # 提取其他资源链接
        资源模式 = r'src="([^"]+)"'
        资源列表 = re.findall(资源模式, HTML内容, re.IGNORECASE)
        for 资源 in 资源列表:
            self._添加URL(资源)
    
    def _添加URL(self, URL):
        """添加并清理 URL"""
        # 解码 HTML 实体
        清理后的URL = html.unescape(URL)
        # 移除跟踪参数
        if '?' in 清理后的URL:
            基础URL = 清理后的URL.split('?')[0]
        else:
            基础URL = 清理后的URL
        
        # 添加到结果
        解析结果 = urlparse(清理后的URL)
        self.分析结果['URL信息'].append({
            '原始URL': 清理后的URL,
            '基础URL': 基础URL,
            '域名': 解析结果.netloc,
            '路径': 解析结果.path
        })
    
    def 提取正文内容(self):
        """提取邮件正文内容"""
        if self.解析后的邮件.is_multipart():
            for 部分 in self.解析后的邮件.walk():
                内容类型 = 部分.get_content_type()
                内容描述 = str(部分.get("Content-Disposition"))
                
                # 跳过附件
                if "attachment" in 内容描述:
                    continue
                
                # 提取文本正文
                if 内容类型 == "text/plain":
                    内容载荷 = 部分.get_payload(decode=True)
                    if 内容载荷:
                        字符集 = 部分.get_content_charset('utf-8')
                        try:
                            文本内容 = 内容载荷.decode(字符集, errors='replace')
                            self.分析结果['正文内容']['文本'] += 文本内容
                        except:
                            try:
                                文本内容 = 内容载荷.decode('latin-1', errors='replace')
                                self.分析结果['正文内容']['文本'] += 文本内容
                            except:
                                self.分析结果['正文内容']['文本'] += str(内容载荷)
                
                # 提取 HTML 正文
                elif 内容类型 == "text/html":
                    内容载荷 = 部分.get_payload(decode=True)
                    if 内容载荷:
                        字符集 = 部分.get_content_charset('utf-8')
                        try:
                            HTML内容 = 内容载荷.decode(字符集, errors='replace')
                            self.分析结果['正文内容']['HTML'] += HTML内容
                        except:
                            try:
                                HTML内容 = 内容载荷.decode('latin-1', errors='replace')
                                self.分析结果['正文内容']['HTML'] += HTML内容
                            except:
                                self.分析结果['正文内容']['HTML'] += str(内容载荷)
        else:
            # 单部分邮件
            内容载荷 = self.解析后的邮件.get_payload(decode=True)
            if 内容载荷:
                字符集 = self.解析后的邮件.get_content_charset('utf-8')
                if self.解析后的邮件.get_content_type() == "text/plain":
                    try:
                        self.分析结果['正文内容']['文本'] = 内容载荷.decode(字符集, errors='replace')
                    except:
                        try:
                            self.分析结果['正文内容']['文本'] = 内容载荷.decode('latin-1', errors='replace')
                        except:
                            self.分析结果['正文内容']['文本'] = str(内容载荷)
                elif self.解析后的邮件.get_content_type() == "text/html":
                    try:
                        self.分析结果['正文内容']['HTML'] = 内容载荷.decode(字符集, errors='replace')
                    except:
                        try:
                            self.分析结果['正文内容']['HTML'] = 内容载荷.decode('latin-1', errors='replace')
                        except:
                            self.分析结果['正文内容']['HTML'] = str(内容载荷)
        
        # 统计内容长度
        self.分析结果['内容统计']['文本字符数'] = len(self.分析结果['正文内容']['文本'])
        self.分析结果['内容统计']['HTML字符数'] = len(self.分析结果['正文内容']['HTML'])
    
    def 提取附件信息(self):
        """提取邮件附件信息"""
        if self.解析后的邮件.is_multipart():
            for 部分 in self.解析后的邮件.walk():
                内容描述 = str(部分.get("Content-Disposition"))
                if "attachment" in 内容描述 or "filename" in 内容描述:
                    文件名 = 部分.get_filename()
                    内容类型 = 部分.get_content_type()
                    内容载荷 = 部分.get_payload(decode=True)
                    大小 = len(内容载荷) if 内容载荷 else 0
                    
                    # 处理文件名编码
                    if 文件名:
                        解码后的文件名 = email.header.decode_header(文件名)[0][0]
                        if isinstance(解码后的文件名, bytes):
                            try:
                                文件名 = 解码后的文件名.decode('utf-8')
                            except:
                                try:
                                    文件名 = 解码后的文件名.decode('latin-1', errors='replace')
                                except:
                                    文件名 = str(解码后的文件名)
                    
                    # 添加到结果
                    self.分析结果['附件信息'].append({
                        '文件名': 文件名 or '未命名',
                        '内容类型': 内容类型,
                        '大小': f"{大小} 字节",
                        'MD5': self._计算MD5(内容载荷) if 内容载荷 and 大小 > 0 else '无'
                    })
    
    def _计算MD5(self, 数据):
        """计算 MD5 哈希值"""
        return hashlib.md5(数据).hexdigest()
    
    def 提取二维码信息(self):
        """提取邮件中的二维码"""
        # 从 HTML 正文中提取 Base64 图片
        HTML正文 = self.分析结果['正文内容']['HTML']
        if HTML正文:
            self._扫描Base64图片(HTML正文)
        
        # 从附件中提取图片
        for 附件 in self.分析结果['附件信息']:
            if 附件['内容类型'].startswith('image/'):
                对应部分 = next((部分 for 部分 in self.解析后的邮件.walk() 
                           if str(部分.get("Content-Disposition", '')).startswith('attachment')), None)
                if 对应部分:
                    内容载荷 = 对应部分.get_payload(decode=True)
                    if 内容载荷:
                        self._扫描图片中的二维码(内容载荷, f"附件: {附件['文件名']}")
    
    def _扫描Base64图片(self, HTML内容):
        """扫描 HTML 中的 Base64 图片"""
        base64模式 = r'src="data:image/[^;]+;base64,([^"]+)"'
        base64图片列表 = re.findall(base64模式, HTML内容, re.IGNORECASE)
        
        for 序号, 图片数据 in enumerate(base64图片列表):
            try:
                图片字节 = base64.b64decode(图片数据)
                self._扫描图片中的二维码(图片字节, f"HTML Base64 图片 #{序号+1}")
            except Exception as e:
                pass
    
    def _扫描图片中的二维码(self, 图片数据, 来源):
        """扫描图片中的二维码"""
        try:
            图片 = Image.open(BytesIO(图片数据))
            解码结果 = pyzbar.decode(图片)
            
            for 结果 in 解码结果:
                try:
                    二维码数据 = 结果.data.decode('utf-8')
                except:
                    二维码数据 = str(结果.data)
                    
                self.分析结果['二维码信息'].append({
                    '来源': 来源,
                    '类型': 结果.type,
                    '数据': 二维码数据,
                    '图片尺寸': f"{图片.width}x{图片.height}"
                })
        except Exception as e:
            pass
    
    def 执行分析(self):
        """执行完整分析"""
        self.解析邮件()
        self.提取邮件头信息()
        self.提取发件人路由()
        self.提取正文内容()
        self.提取收件人列表()
        self.提取URL信息()
        self.提取附件信息()
        self.提取二维码信息()
        return self.分析结果
    
    def 生成报告(self, 输出目录='分析报告'):
        """生成美观的中文分析报告"""
        if not os.path.exists(输出目录):
            os.makedirs(输出目录)
        
        # 创建基础文件名
        时间戳 = datetime.now().strftime('%Y%m%d_%H%M%S')
        报告名称 = f"邮件分析报告_{时间戳}"
        csv路径 = os.path.join(输出目录, f"{报告名称}.csv")
        txt路径 = os.path.join(输出目录, f"{报告名称}.txt")
        
        # 生成完整正文文件
        文本正文路径 = os.path.join(输出目录, f"{报告名称}_完整文本正文.txt")
        HTML正文路径 = os.path.join(输出目录, f"{报告名称}_完整HTML正文.html")
        
        # 保存完整文本正文
        with open(文本正文路径, 'w', encoding='utf-8') as 文本文件:
            文本文件.write(self.分析结果['正文内容']['文本'])
        
        # 保存完整HTML正文
        with open(HTML正文路径, 'w', encoding='utf-8') as HTML文件:
            HTML文件.write(self.分析结果['正文内容']['HTML'])
        
        # 生成 CSV 报告
        with open(csv路径, 'w', newline='', encoding='utf-8-sig') as csv文件:  # utf-8-sig 支持Excel中文
            写入器 = csv.writer(csv文件)
            
            # 邮件头信息
            写入器.writerow(['分析类型', '详细信息'])
            写入器.writerow(['邮件头信息', ''])
            for 头字段, 值 in self.分析结果['邮件头信息'].items():
                写入器.writerow([头字段, 值])
            写入器.writerow([])
            
            # 发件人路由
            写入器.writerow(['发件人路由', ''])
            for 序号, 路由 in enumerate(self.分析结果['发件人路由'], 1):
                写入器.writerow([f'路由节点 {序号}', 路由])
            写入器.writerow([])
            
            # 收件人
            写入器.writerow(['收件人列表', ''])
            for 类型, 地址列表 in self.分析结果['收件人列表'].items():
                if 地址列表:
                    写入器.writerow([类型, ', '.join(地址列表)])
            写入器.writerow([])
            
            # URL
            写入器.writerow(['URL信息', ''])
            写入器.writerow(['原始URL', '基础URL', '域名', '路径'])
            for url信息 in self.分析结果['URL信息']:
                写入器.writerow([
                    url信息['原始URL'],
                    url信息['基础URL'],
                    url信息['域名'],
                    url信息['路径']
                ])
            写入器.writerow([])
            
            # 附件
            写入器.writerow(['附件信息', ''])
            写入器.writerow(['文件名', '内容类型', '大小', 'MD5哈希'])
            for 附件 in self.分析结果['附件信息']:
                写入器.writerow([
                    附件['文件名'],
                    附件['内容类型'],
                    附件['大小'],
                    附件['MD5']
                ])
            写入器.writerow([])
            
            # 二维码
            写入器.writerow(['二维码信息', ''])
            写入器.writerow(['来源', '类型', '数据', '图片尺寸'])
            for 二维码 in self.分析结果['二维码信息']:
                写入器.writerow([
                    二维码['来源'],
                    二维码['类型'],
                    二维码['数据'],
                    二维码['图片尺寸']
                ])
        
        # 生成美观的文本报告
        with open(txt路径, 'w', encoding='utf-8') as 文本文件:
            # 报告标题
            分隔线 = "=" * 80
            标题 = f"恶意邮件分析报告: {os.path.basename(self.eml文件路径)}"
            文本文件.write(f"{分隔线}\n{标题.center(80)}\n{分隔线}\n\n")
            
            # 基本信息摘要
            文本文件.write("[📧 基本信息摘要]\n")
            文本文件.write("-" * 80 + "\n")
            文本文件.write(f"发件人: {self.分析结果['邮件头信息'].get('From', '未知')}\n")
            文本文件.write(f"主题: {self.分析结果['邮件头信息'].get('Subject', '无主题')}\n")
            文本文件.write(f"日期: {self.分析结果['邮件头信息'].get('Date', '未知')}\n")
            文本文件.write(f"路由节点数: {len(self.分析结果['发件人路由'])}\n")
            文本文件.write(f"URL数量: {len(self.分析结果['URL信息'])}\n")
            文本文件.write(f"附件数量: {len(self.分析结果['附件信息'])}\n")
            文本文件.write(f"二维码数量: {len(self.分析结果['二维码信息'])}\n")
            文本文件.write(f"文本正文长度: {self.分析结果['内容统计']['文本字符数']} 字符\n")
            文本文件.write(f"HTML正文长度: {self.分析结果['内容统计']['HTML字符数']} 字符\n\n")
            
            # 邮件头信息
            文本文件.write("[📋 邮件头信息]\n")
            文本文件.write("-" * 80 + "\n")
            for 头字段, 值 in self.分析结果['邮件头信息'].items():
                # 对长值进行换行处理
                格式化值 = textwrap.fill(值, width=78, subsequent_indent=' ' * (len(头字段) + 3)) 
                文本文件.write(f"{头字段}: {格式化值}\n")
            文本文件.write("\n")
            
            # 发件人路由
            文本文件.write("[🛣️ 发件人路由]\n")
            文本文件.write("-" * 80 + "\n")
            if self.分析结果['发件人路由']:
                for 序号, 路由 in enumerate(self.分析结果['发件人路由'], 1):
                    文本文件.write(f"路由节点 {序号}:\n")
                    文本文件.write(f"  {路由}\n\n")
            else:
                文本文件.write("未找到路由信息\n")
            文本文件.write("\n")
            
            # 收件人
            文本文件.write("[👥 收件人列表]\n")
            文本文件.write("-" * 80 + "\n")
            for 类型, 地址列表 in self.分析结果['收件人列表'].items():
                if 地址列表:
                    文本文件.write(f"{类型}:\n")
                    for 地址 in 地址列表:
                        文本文件.write(f"  - {地址}\n")
                    文本文件.write("\n")
            文本文件.write("\n")
            
            # URL
            文本文件.write("[🔗 URL信息]\n")
            文本文件.write("-" * 80 + "\n")
            if self.分析结果['URL信息']:
                for 序号, url信息 in enumerate(self.分析结果['URL信息'], 1):
                    文本文件.write(f"URL {序号}:\n")
                    文本文件.write(f"  原始URL: {url信息['原始URL']}\n")
                    文本文件.write(f"  基础URL: {url信息['基础URL']}\n")
                    文本文件.write(f"  域名: {url信息['域名']}\n")
                    文本文件.write(f"  路径: {url信息['路径']}\n\n")
            else:
                文本文件.write("未找到URL\n")
            文本文件.write("\n")
            
            # 附件
            文本文件.write("[📎 附件信息]\n")
            文本文件.write("-" * 80 + "\n")
            if self.分析结果['附件信息']:
                for 附件 in self.分析结果['附件信息']:
                    文本文件.write(f"文件名: {附件['文件名']}\n")
                    文本文件.write(f"类型: {附件['内容类型']}\n")
                    文本文件.write(f"大小: {附件['大小']}\n")
                    文本文件.write(f"MD5: {附件['MD5']}\n\n")
            else:
                文本文件.write("未找到附件\n")
            文本文件.write("\n")
            
            # 二维码
            文本文件.write("[📱 二维码信息]\n")
            文本文件.write("-" * 80 + "\n")
            if self.分析结果['二维码信息']:
                for 二维码 in self.分析结果['二维码信息']:
                    文本文件.write(f"来源: {二维码['来源']}\n")
                    文本文件.write(f"类型: {二维码['类型']}\n")
                    文本文件.write(f"数据: {二维码['数据']}\n")
                    文本文件.write(f"图片尺寸: {二维码['图片尺寸']}\n\n")
            else:
                文本文件.write("未找到二维码\n")
            文本文件.write("\n")
            
            # 正文内容 - 大幅增加展示长度
            文本文件.write("[📝 文本正文 (前15000字符)]\n")
            文本文件.write("-" * 80 + "\n")
            if self.分析结果['正文内容']['文本']:
                文本正文 = self.分析结果['正文内容']['文本']
                # 对长文本进行格式化
                截断位置 = 15000
                if len(文本正文) > 截断位置:
                    显示文本 = 文本正文[:截断位置]
                    截断提示 = f"\n[...已截断，完整内容见: {os.path.basename(文本正文路径)} ...]"
                else:
                    显示文本 = 文本正文
                    截断提示 = ""
                
                格式化文本 = textwrap.fill(显示文本, width=78) 
                文本文件.write(格式化文本 + 截断提示)
            else:
                文本文件.write("无文本正文内容\n")
            文本文件.write("\n\n")
            
            文本文件.write("[🌐 HTML正文 (前15000字符)]\n")
            文本文件.write("-" * 80 + "\n")
            if self.分析结果['正文内容']['HTML']:
                HTML正文 = self.分析结果['正文内容']['HTML']
                # 提取纯文本内容
                纯文本 = re.sub(r'<[^>]+>', '', HTML正文)  # 移除HTML标签
                纯文本 = re.sub(r'\s+', ' ', 纯文本)  # 合并空格
                
                截断位置 = 15000
                if len(纯文本) > 截断位置:
                    显示文本 = 纯文本[:截断位置]
                    截断提示 = f"\n[...已截断，完整内容见: {os.path.basename(HTML正文路径)} ...]"
                else:
                    显示文本 = 纯文本
                    截断提示 = ""
                
                格式化文本 = textwrap.fill(显示文本, width=78)
                文本文件.write(格式化文本 + 截断提示)
            else:
                文本文件.write("无HTML正文内容\n")
            文本文件.write("\n")
            
            # 完整内容指引
            文本文件.write("[💾 完整内容文件]\n")
            文本文件.write("-" * 80 + "\n")
            文本文件.write(f"完整文本正文已保存至: {文本正文路径}\n")
            文本文件.write(f"完整HTML正文已保存至: {HTML正文路径}\n")
            
            文本文件.write("\n" + "=" * 80 + "\n")
            文本文件.write("分析完成时间: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            if os.name == 'nt':  # Windows系统
                文本文件.write("\n报告保存位置: " + os.path.abspath(输出目录).replace('\\', '/'))
            else:
                文本文件.write("\n报告保存位置: " + os.path.abspath(输出目录))
        
        return csv路径, txt路径, 文本正文路径, HTML正文路径

# 主程序
if __name__ == "__main__":
    # 检查命令行参数
    if len(sys.argv) < 2:
        print("使用方法: python 邮件分析工具.py <邮件文件路径>")
        sys.exit(1)
    
    邮件路径 = sys.argv[1]
    
    if not os.path.exists(邮件路径):
        print(f"错误: 文件不存在 - {邮件路径}")
        sys.exit(1)
    
    # 初始化分析器
    print(f"🔍 开始分析邮件: {os.path.basename(邮件路径)}")
    分析器 = 恶意邮件分析器(邮件路径)
    
    # 执行分析
    try:
        print("🔄 正在解析邮件内容...")
        结果 = 分析器.执行分析()
        
        print("📊 正在生成报告...")
        csv报告路径, txt报告路径, 文本正文路径, HTML正文路径 = 分析器.生成报告()
        
        print("\n✅ 分析完成! 报告已保存至:")
        print(f"- CSV格式报告: {csv报告路径}")
        print(f"- 文本格式报告: {txt报告路径}")
        print(f"- 完整文本正文: {文本正文路径}")
        print(f"- 完整HTML正文: {HTML正文路径}")
        
        # 打印摘要信息
        print("\n📋 分析摘要:")
        print(f"发件人: {结果['邮件头信息'].get('From', '未知')}")
        print(f"主题: {结果['邮件头信息'].get('Subject', '无主题')}")
        print(f"路由节点数: {len(结果['发件人路由'])}")
        收件人总数 = sum(len(v) for v in 结果['收件人列表'].values())
        print(f"收件人总数: {收件人总数}")
        print(f"发现URL数量: {len(结果['URL信息'])}")
        print(f"发现附件数量: {len(结果['附件信息'])}")
        print(f"发现二维码数量: {len(结果['二维码信息'])}")
        print(f"文本正文长度: {结果['内容统计']['文本字符数']} 字符")
        print(f"HTML正文长度: {结果['内容统计']['HTML字符数']} 字符")
    
    except Exception as 错误:
        print(f"❌ 分析过程中出错: {str(错误)}")
        import traceback
        traceback.print_exc()
