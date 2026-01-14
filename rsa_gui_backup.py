import tkinter as tk
import os
from tkinter import ttk, messagebox, filedialog
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64
import time

class RSAEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA本地加密工具")
        self.root.geometry("500x400")  # 减小窗口大小
        self.root.resizable(True, True)
        
        # 初始化密钥
        self.private_key = None
        self.public_key = None
        
        # 密钥列表 - 用于多密钥管理
        self.private_keys = []  # 存储私钥对象和相关信息
        self.public_keys = []   # 存储公钥对象和相关信息
        
        # 当前选择的密钥索引
        self.selected_private_key_idx = -1
        self.selected_public_key_idx = -1
        
        # 加载已保存的密钥
        self.load_saved_keys()
        
        # 设置UI样式
        self.setup_styles()
        
        # 创建界面
        self.create_widgets()
        
        # 创建临时消息标签
        self.temp_message_label = ttk.Label(self.root, text="", foreground="#4caf50")
        self.temp_message_label.pack(pady=2)
    
    def load_saved_keys(self):
        """加载已保存的密钥文件"""
        try:
            # 清空当前密钥列表
            self.private_keys.clear()
            self.public_keys.clear()
            
            # 检查key文件夹是否存在
            if not os.path.exists("key"):
                return
            
            # 遍历文件夹中的所有文件
            for filename in os.listdir("key"):
                if filename.endswith(".pem"):
                    file_path = os.path.join("key", filename)
                    
                    try:
                        with open(file_path, "rb") as f:
                            key_data = f.read()
                        
                        # 根据文件名判断密钥类型
                        if filename.startswith("private_"):
                            # 加载私钥
                            private_key = serialization.load_pem_private_key(
                                key_data,
                                password=None,
                                backend=default_backend()
                            )
                            # 从文件名中提取时间戳
                            timestamp = filename.split("_")[1].split(".")[0]
                            # 默认备注为空
                            remark = ""
                            # 检查是否有对应的备注文件
                            remark_file = os.path.join("key", f"private_{timestamp}.txt")
                            if os.path.exists(remark_file):
                                with open(remark_file, "r", encoding="utf-8") as f:
                                    remark = f.read().strip()
                            # 添加到私钥列表
                            self.private_keys.append({
                                "key": private_key,
                                "path": file_path,
                                "timestamp": timestamp,
                                "remark": remark
                            })
                        elif filename.startswith("public_"):
                            # 加载公钥
                            public_key = serialization.load_pem_public_key(
                                key_data,
                                backend=default_backend()
                            )
                            # 从文件名中提取时间戳
                            timestamp = filename.split("_")[1].split(".")[0]
                            # 默认备注为空
                            remark = ""
                            # 检查是否有对应的备注文件
                            remark_file = os.path.join("key", f"public_{timestamp}.txt")
                            if os.path.exists(remark_file):
                                with open(remark_file, "r", encoding="utf-8") as f:
                                    remark = f.read().strip()
                            # 添加到公钥列表
                            self.public_keys.append({
                                "key": public_key,
                                "path": file_path,
                                "timestamp": timestamp,
                                "remark": remark
                            })
                    except Exception as e:
                        print(f"加载密钥文件 {filename} 失败: {str(e)}")
            
            # 如果有密钥，默认选择第一个
            if self.private_keys:
                self.selected_private_key_idx = 0
                self.private_key = self.private_keys[0]["key"]
                # 从私钥中提取公钥
                self.public_key = self.private_key.public_key()
            elif self.public_keys:
                self.selected_public_key_idx = 0
                self.public_key = self.public_keys[0]["key"]
            
            # 更新密钥下拉框
            if hasattr(self, 'update_key_comboboxes'):
                self.update_key_comboboxes()
        except Exception as e:
            print(f"加载密钥失败: {str(e)}")
    
    def setup_styles(self):
        # 创建自定义样式
        style = ttk.Style()
        
        # 设置主题
        style.theme_use("clam")  # 使用clam主题，更现代的外观
        
        # 设置全局背景色
        self.root.configure(bg="#f0f0f0")
        
        # 配置按钮样式
        style.configure("TButton",
                       font=('Helvetica', 9),
                       padding=5,
                       relief="flat",
                       background="#d4d4d4",
                       foreground="#333333")
        
        style.map("TButton",
                 background=[("active", "#bdbdbd")],
                 foreground=[("active", "#000000")])
        
        style.configure("Accent.TButton",
                       font=('Helvetica', 9, 'bold'),
                       padding=6,
                       foreground="#333333",
                       background="#e0e0e0")
        
        style.map("Accent.TButton",
                 background=[("active", "#bdbdbd")],
                 foreground=[("active", "#000000")])
        
        # 配置标签框架样式
        style.configure("TLabelframe.Label",
                       font=('Helvetica', 10, 'bold'),
                       foreground="#424242")
        
        style.configure("TLabelframe",
                       borderwidth=2,
                       relief="flat",
                       background="#ffffff")
        
        # 配置文本框样式
        style.configure("TEntry",
                       padding=4,
                       font=('Helvetica', 9),
                       background="#ffffff",
                       foreground="#333333",
                       borderwidth=1,
                       relief="flat")
    
    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")  # 进一步减小内边距
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(main_frame, text="RSA加密工具", font=('Helvetica', 15, 'bold'))
        title_label.pack(pady=5)
        
        # 密钥管理按钮
        key_manage_btn = ttk.Button(main_frame, text="密钥管理", command=self.open_key_management, style="Accent.TButton")
        key_manage_btn.pack(fill=tk.X, pady=5)
        
        # 输入部分 - 明文/密文输入
        input_frame = ttk.LabelFrame(main_frame, text="输入", padding="8")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=3)
        
        # 输入框和粘贴按钮
        input_inner_frame = ttk.Frame(input_frame)
        input_inner_frame.pack(fill=tk.X)
        
        # 创建一个Frame来容纳Text和Scrollbar
        text_frame = ttk.Frame(input_inner_frame)
        text_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.input_text = tk.Text(text_frame, height=5, width=50, bg="#ffffff", fg="#333333",
                               font=('Helvetica', 9), borderwidth=1, relief="solid")  # 添加样式
        self.input_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 添加垂直滚动条
        input_scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.input_text.yview)
        input_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.input_text.configure(yscrollcommand=input_scrollbar.set)
        
        paste_btn = ttk.Button(input_inner_frame, text="粘贴", command=self.paste_to_input, width=8)
        paste_btn.pack(side=tk.RIGHT)
        
        # 操作按钮部分 - 加密和解密
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=5)
        
        # 使用网格布局放置按钮和下拉框，更紧凑的布局
        action_frame.columnconfigure(0, weight=0, minsize=60)
        action_frame.columnconfigure(1, weight=1)
        action_frame.columnconfigure(2, weight=0, minsize=60)
        action_frame.columnconfigure(3, weight=1)
        
        # 加密部分
        encrypt_btn = ttk.Button(action_frame, text="加密", command=self.encrypt_message, style="Accent.TButton", width=6)
        encrypt_btn.grid(row=0, column=0, padx=(0, 5), pady=2, sticky=tk.EW)
        
        # 公钥选择下拉框
        self.public_key_var = tk.StringVar()
        self.public_key_combobox = ttk.Combobox(action_frame, textvariable=self.public_key_var, state="readonly", width=20)
        self.public_key_combobox.grid(row=0, column=1, padx=(0, 10), pady=2, sticky=tk.EW)
        self.public_key_combobox.bind("<<ComboboxSelected>>", self.on_public_key_selected)
        
        # 解密部分
        decrypt_btn = ttk.Button(action_frame, text="解密", command=self.decrypt_message, width=6)
        decrypt_btn.grid(row=0, column=2, padx=(0, 5), pady=2, sticky=tk.EW)
        
        # 私钥选择下拉框
        self.private_key_var = tk.StringVar()
        self.private_key_combobox = ttk.Combobox(action_frame, textvariable=self.private_key_var, state="readonly", width=20)
        self.private_key_combobox.grid(row=0, column=3, pady=2, sticky=tk.EW)
        self.private_key_combobox.bind("<<ComboboxSelected>>", self.on_private_key_selected)
        
        # 初始化密钥下拉框
        self.update_key_comboboxes()
        
        # 输出部分 - 密文/明文输出
        output_frame = ttk.LabelFrame(main_frame, text="输出", padding="8")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=3)
        
        # 输出框和复制按钮
        output_inner_frame = ttk.Frame(output_frame)
        output_inner_frame.pack(fill=tk.X)
        
        # 创建一个Frame来容纳Text和Scrollbar
        text_frame = ttk.Frame(output_inner_frame)
        text_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.output_text = tk.Text(text_frame, height=5, width=50, state=tk.DISABLED,
                                bg="#ffffff", fg="#333333", font=('Helvetica', 9),
                                borderwidth=1, relief="solid")  # 添加样式
        self.output_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 添加垂直滚动条
        output_scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.output_text.yview)
        output_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.configure(yscrollcommand=output_scrollbar.set)
        
        copy_btn = ttk.Button(output_inner_frame, text="复制", command=self.copy_from_output, width=8)
        copy_btn.pack(side=tk.RIGHT)
        
        # 状态标签
        self.status_label = ttk.Label(main_frame, text="等待操作...", foreground="#666666", font=('Helvetica', 9))
        self.status_label.pack(pady=3)
    
    def generate_keys(self):
        try:
            self.status_label.config(text="正在生成密钥对...")
            self.root.update()
            
            # 生成RSA密钥对
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            # 创建key文件夹（如果不存在）
            if not os.path.exists("key"):
                os.makedirs("key")
            
            # 使用时间戳作为文件名，确保唯一性
            timestamp = str(int(time.time()))
            
            # 序列化并保存私钥
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            private_key_path = os.path.join("key", f"private_{timestamp}.pem")
            with open(private_key_path, "wb") as f:
                f.write(private_pem)
            
            # 序列化并保存公钥
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            public_key_path = os.path.join("key", f"public_{timestamp}.pem")
            with open(public_key_path, "wb") as f:
                f.write(public_pem)
            
            # 获取备注信息
            remark = ""
            if hasattr(self, 'key_remark_entry'):
                remark = self.key_remark_entry.get().strip()
                # 如果是默认提示文字，则不保存
                if remark == "例如：工作密钥、个人密钥":
                    remark = ""
            
            # 保存备注文件
            if remark:
                private_remark_file = os.path.join("key", f"private_{timestamp}.txt")
                with open(private_remark_file, "w", encoding="utf-8") as f:
                    f.write(remark)
                
                public_remark_file = os.path.join("key", f"public_{timestamp}.txt")
                with open(public_remark_file, "w", encoding="utf-8") as f:
                    f.write(remark)
            
            # 重新加载密钥列表
            self.load_saved_keys()
            
            # 显示自动消失的成功提示
            self.show_temporary_message("RSA密钥对生成并保存成功！")
            self.status_label.config(text="密钥对已生成")
        except Exception as e:
            messagebox.showerror("错误", f"生成密钥失败: {str(e)}")
            self.status_label.config(text="密钥生成失败")
    
    def import_private_key(self):
        try:
            file_path = filedialog.askopenfilename(
                title="选择私钥文件",
                filetypes=[("PEM文件", "*.pem"), ("所有文件", "*.*")]
            )
            if not file_path:
                return
            
            self.status_label.config(text="正在导入私钥...")
            self.root.update()
            
            with open(file_path, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            
            # 从私钥中提取公钥
            self.public_key = self.private_key.public_key()
            
            # 显示自动消失的成功提示
            self.show_temporary_message("私钥导入成功！")
            self.status_label.config(text="私钥已导入")
        except Exception as e:
            messagebox.showerror("错误", f"导入私钥失败: {str(e)}")
            self.status_label.config(text="私钥导入失败")
    
    def import_public_key(self):
        try:
            file_path = filedialog.askopenfilename(
                title="选择公钥文件",
                filetypes=[("PEM文件", "*.pem"), ("所有文件", "*.*")]
            )
            if not file_path:
                return
            
            self.status_label.config(text="正在导入公钥...")
            self.root.update()
            
            with open(file_path, "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            
            # 显示自动消失的成功提示
            self.show_temporary_message("公钥导入成功！")
            self.status_label.config(text="公钥已导入")
        except Exception as e:
            messagebox.showerror("错误", f"导入公钥失败: {str(e)}")
            self.status_label.config(text="公钥导入失败")
    
    def show_temporary_message(self, message, duration=2000):
        # 显示临时消息
        self.temp_message_label.config(text=message, foreground="#4caf50")
        self.temp_message_label.pack(pady=2)
        
        # 定时隐藏消息
        self.root.after(duration, lambda: self.temp_message_label.pack_forget())
    
    def encrypt_message(self):
        try:
            if not self.public_key:
                messagebox.showwarning("警告", "请先生成密钥对！")
                return
            
            plaintext = self.input_text.get("1.0", tk.END).strip()
            if not plaintext:
                messagebox.showwarning("警告", "请输入要加密的明文！")
                return
            
            self.status_label.config(text="正在加密...")
            self.root.update()
            
            # 加密消息
            encrypted = self.public_key.encrypt(
                plaintext.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # 转换为base64格式以便显示
            encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
            
            # 显示结果
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, encrypted_b64)
            self.output_text.config(state=tk.DISABLED)
            
            # 显示自动消失的成功提示
            self.show_temporary_message("加密完成！")
            self.status_label.config(text="加密完成")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")
            self.status_label.config(text="加密失败")
    
    def decrypt_message(self):
        try:
            if not self.private_key:
                messagebox.showwarning("警告", "请先生成密钥对！")
                return
            
            ciphertext_b64 = self.input_text.get("1.0", tk.END).strip()
            if not ciphertext_b64:
                messagebox.showwarning("警告", "请输入要解密的密文！")
                return
            
            self.status_label.config(text="正在解密...")
            self.root.update()
            
            # 从base64转换回字节
            ciphertext = base64.b64decode(ciphertext_b64)
            
            # 解密消息
            decrypted = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # 显示结果
            decrypted_text = decrypted.decode('utf-8')
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted_text)
            self.output_text.config(state=tk.DISABLED)
            
            # 显示自动消失的成功提示
            self.show_temporary_message("解密完成！")
            self.status_label.config(text="解密完成")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")
            self.status_label.config(text="解密失败")
    
    def paste_to_input(self):
        try:
            # 获取剪贴板内容
            content = self.root.clipboard_get()
            # 清空当前输入
            self.input_text.delete("1.0", tk.END)
            # 粘贴剪贴板内容
            self.input_text.insert(tk.END, content)
        except tk.TclError:
            messagebox.showwarning("警告", "剪贴板为空或无法访问！")
    
    def copy_from_output(self):
        try:
            # 获取输出内容
            content = self.output_text.get("1.0", tk.END).strip()
            if not content:
                messagebox.showwarning("警告", "没有可复制的内容！")
                return
            # 将内容复制到剪贴板
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            # 显示自动消失的成功提示
            self.show_temporary_message("内容已复制到剪贴板！")
        except Exception as e:
            messagebox.showerror("错误", f"复制失败: {str(e)}")
    
    def update_key_comboboxes(self):
        """更新密钥选择下拉框的内容"""
        # 检查下拉框是否已经创建
        if not hasattr(self, 'public_key_combobox') or not hasattr(self, 'private_key_combobox'):
            return
            
        # 更新公钥下拉框
        public_key_options = []
        for i, key_info in enumerate(self.public_keys):
            remark = key_info["remark"]
            timestamp = key_info["timestamp"]
            option_text = remark if remark else f"公钥 {i+1} ({timestamp})"
            public_key_options.append(option_text)
        
        self.public_key_combobox['values'] = public_key_options
        if public_key_options and self.selected_public_key_idx >= 0 and self.selected_public_key_idx < len(public_key_options):
            self.public_key_var.set(public_key_options[self.selected_public_key_idx])
        elif public_key_options:
            self.public_key_var.set(public_key_options[0])
        else:
            self.public_key_var.set("")
        
        # 更新私钥下拉框
        private_key_options = []
        for i, key_info in enumerate(self.private_keys):
            remark = key_info["remark"]
            timestamp = key_info["timestamp"]
            option_text = remark if remark else f"私钥 {i+1} ({timestamp})"
            private_key_options.append(option_text)
        
        self.private_key_combobox['values'] = private_key_options
        if private_key_options and self.selected_private_key_idx >= 0 and self.selected_private_key_idx < len(private_key_options):
            self.private_key_var.set(private_key_options[self.selected_private_key_idx])
        elif private_key_options:
            self.private_key_var.set(private_key_options[0])
        else:
            self.private_key_var.set("")
    
    def on_public_key_selected(self, event):
        """处理公钥选择事件"""
        selected_idx = self.public_key_combobox.current()
        if selected_idx >= 0 and selected_idx < len(self.public_keys):
            self.public_key = self.public_keys[selected_idx]["key"]
            self.selected_public_key_idx = selected_idx
            self.status_label.config(text=f"已选择公钥 {selected_idx+1}")
    
    def on_private_key_selected(self, event):
        """处理私钥选择事件"""
        selected_idx = self.private_key_combobox.current()
        if selected_idx >= 0 and selected_idx < len(self.private_keys):
            self.private_key = self.private_keys[selected_idx]["key"]
            # 同时更新公钥（从私钥中提取）
            self.public_key = self.private_key.public_key()
            self.selected_private_key_idx = selected_idx
            self.status_label.config(text=f"已选择私钥 {selected_idx+1}")
    
    def open_key_management(self):
        # 创建密钥管理窗口
        key_window = tk.Toplevel(self.root)
        key_window.title("密钥管理")
        key_window.geometry("450x600")  # 调整窗口大小
        key_window.resizable(False, False)
        key_window.grab_set()  # 模态窗口
        key_window.configure(bg="#f5f5f5")  # 统一背景色
        
        # 中心定位
        key_window.transient(self.root)
        key_window.geometry(f"+{self.root.winfo_x()+50}+{self.root.winfo_y()+50}")
        
        # 使用Canvas和Scrollbar来支持滚动
        canvas = tk.Canvas(key_window, bg="#f5f5f5")
        scrollbar = ttk.Scrollbar(key_window, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # 密钥管理窗口框架
        key_frame = ttk.Frame(scrollable_frame, padding="15")
        key_frame.pack(fill=tk.X, expand=False)
        
        # 标题
        key_title = ttk.Label(key_frame, text="密钥管理", font=('Helvetica', 13, 'bold'))
        key_title.pack(pady=10)
        
        # 操作按钮 - 生成密钥对按钮放在最前面，确保可见
        btn_frame = ttk.Frame(key_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        generate_btn = ttk.Button(btn_frame, text="生成密钥对", command=lambda: [self.generate_keys(), load_key_list(), update_key_status()], style="Accent.TButton")
        generate_btn.pack(fill=tk.X, padx=2, pady=2)
        
        import_private_btn = ttk.Button(btn_frame, text="导入私钥", command=lambda: [self.import_private_key(), load_key_list(), update_key_status()])
        import_private_btn.pack(fill=tk.X, padx=2, pady=2)
        
        import_public_btn = ttk.Button(btn_frame, text="导入公钥", command=lambda: [self.import_public_key(), load_key_list(), update_key_status()])
        import_public_btn.pack(fill=tk.X, padx=2, pady=2)
        
        # 密钥状态
        key_status_frame = ttk.LabelFrame(key_frame, text="密钥状态", padding="8")
        key_status_frame.pack(fill=tk.X, expand=False, pady=5)
        
        def update_key_status():
            # 清除所有子组件
            for widget in key_status_frame.winfo_children():
                widget.destroy()
            
            if self.public_key:
                ttk.Label(key_status_frame, text="✓ 已加载公钥", foreground="#4caf50").pack(anchor=tk.W, pady=1)
            else:
                ttk.Label(key_status_frame, text="✗ 未加载公钥", foreground="#f44336").pack(anchor=tk.W, pady=1)
            
            if self.private_key:
                ttk.Label(key_status_frame, text="✓ 已加载私钥", foreground="#4caf50").pack(anchor=tk.W, pady=1)
            else:
                ttk.Label(key_status_frame, text="✗ 未加载私钥", foreground="#f44336").pack(anchor=tk.W, pady=1)
        
        update_key_status()
        
        # 密钥列表框架
        key_list_frame = ttk.LabelFrame(key_frame, text="已保存密钥", padding="8")
        key_list_frame.pack(fill=tk.X, expand=False, pady=5)
        
        # 创建列表框和滚动条
        listbox_frame = ttk.Frame(key_list_frame)
        listbox_frame.pack(fill=tk.X, expand=False)
        
        # 滚动条
        listbox_scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
        listbox_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 密钥列表框
        self.key_listbox = tk.Listbox(listbox_frame, yscrollcommand=listbox_scrollbar.set, font=('Helvetica', 9), height=10, width=45)
        self.key_listbox.pack(side=tk.LEFT, fill=tk.X, expand=False)
        listbox_scrollbar.config(command=self.key_listbox.yview)
        
        # 当前选中的密钥索引
        selected_key_index = tk.IntVar()
        selected_key_index.set(-1)
        
        # 加载密钥列表
        def load_key_list():
            self.key_listbox.delete(0, tk.END)
            # 添加私钥
            for i, key_info in enumerate(self.private_keys):
                remark = key_info["remark"]
                timestamp = key_info["timestamp"]
                item_text = f"[私钥] {remark if remark else f'私钥 {i+1}'} ({timestamp})"
                self.key_listbox.insert(tk.END, item_text)
            # 添加公钥
            for i, key_info in enumerate(self.public_keys):
                remark = key_info["remark"]
                timestamp = key_info["timestamp"]
                item_text = f"[公钥] {remark if remark else f'公钥 {i+1}'} ({timestamp})"
                self.key_listbox.insert(tk.END, item_text)
        
        load_key_list()
        
        # 备注输入框
        remark_frame = ttk.LabelFrame(key_frame, text="密钥备注", padding="8")
        remark_frame.pack(fill=tk.X, pady=5)
        
        self.key_remark_entry = ttk.Entry(remark_frame, font=('Helvetica', 9))
        self.key_remark_entry.pack(fill=tk.X)
        
        # 当前选中的密钥信息
        current_key_info = None
        current_key_type = None  # "private" 或 "public"
        current_key_index = None
        
        # 选择密钥时的处理函数
        def on_key_select(event):
            nonlocal current_key_info, current_key_type, current_key_index
            selected_index = self.key_listbox.curselection()
            if not selected_index:
                return
            
            selected_index = selected_index[0]
            private_key_count = len(self.private_keys)
            
            if selected_index < private_key_count:
                # 选中的是私钥
                current_key_type = "private"
                current_key_index = selected_index
                current_key_info = self.private_keys[selected_index]
                self.key_remark_entry.delete(0, tk.END)
                self.key_remark_entry.insert(0, current_key_info["remark"])
            else:
                # 选中的是公钥
                current_key_type = "public"
                current_key_index = selected_index - private_key_count
                current_key_info = self.public_keys[current_key_index]
                self.key_remark_entry.delete(0, tk.END)
                self.key_remark_entry.insert(0, current_key_info["remark"])
        
        # 保存备注的函数
        def save_remark(*args):
            if current_key_info and current_key_type:
                remark = self.key_remark_entry.get().strip()
                # 更新内存中的备注
                current_key_info["remark"] = remark
                # 保存到文件
                timestamp = current_key_info["timestamp"]
                remark_file = os.path.join("key", f"{current_key_type}_{timestamp}.txt")
                with open(remark_file, "w", encoding="utf-8") as f:
                    f.write(remark)
                # 更新列表框中的显示
                load_key_list()
                # 重新加载密钥以更新主窗口的下拉框
                self.load_saved_keys()
        
        # 绑定选择事件
        self.key_listbox.bind("<<ListboxSelect>>", on_key_select)
        
        # 绑定备注输入框的KeyRelease事件，实现自动保存
        self.key_remark_entry.bind("<KeyRelease>", save_remark)
        
        # 关闭按钮
        close_btn = ttk.Button(key_frame, text="关闭", command=key_window.destroy, style="Accent.TButton")
        close_btn.pack(fill=tk.X, pady=15)
        
        # 布局滚动区域
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAEncryptionGUI(root)
    root.mainloop()