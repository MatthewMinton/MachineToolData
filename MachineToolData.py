import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import hashlib
from datetime import datetime

class ToolDialog:
    """Dialog for adding/editing tool information"""
    
    def __init__(self, parent, title, initial_data=None):
        self.result = None
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("450x350")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        parent.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 225
        y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 175
        self.dialog.geometry(f"+{x}+{y}")
        
        # Create form
        main_frame = tk.Frame(self.dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Tool ID
        tk.Label(main_frame, text="Tool ID:", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.tool_id_entry = tk.Entry(main_frame, width=30)
        self.tool_id_entry.grid(row=0, column=1, pady=5, padx=(10, 0), sticky="ew")
        
        # Description
        tk.Label(main_frame, text="Description:", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        self.description_entry = tk.Entry(main_frame, width=30)
        self.description_entry.grid(row=1, column=1, pady=5, padx=(10, 0), sticky="ew")
        
        # Type
        tk.Label(main_frame, text="Tool Type:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky="w", pady=5)
        self.type_entry = tk.Entry(main_frame, width=30)
        self.type_entry.grid(row=2, column=1, pady=5, padx=(10, 0), sticky="ew")
        
        # Height
        tk.Label(main_frame, text="Height (mm):", font=("Arial", 10, "bold")).grid(row=3, column=0, sticky="w", pady=5)
        self.height_entry = tk.Entry(main_frame, width=30)
        self.height_entry.grid(row=3, column=1, pady=5, padx=(10, 0), sticky="ew")
        
        # Last sharpened
        tk.Label(main_frame, text="Last Sharpened:", font=("Arial", 10, "bold")).grid(row=4, column=0, sticky="w", pady=5)
        date_frame = tk.Frame(main_frame)
        date_frame.grid(row=4, column=1, columnspan=2, pady=5, padx=(10, 0), sticky="ew")
        
        self.date_entry = tk.Entry(date_frame, width=20)
        self.date_entry.pack(side="left", fill="x", expand=True)
        
        today_btn = tk.Button(date_frame, text="Today", 
                             command=self.set_today_date, bg="#2196F3", fg="white", width=8)
        today_btn.pack(side="right", padx=(5, 0))
        
        # Fill with initial data if provided
        if initial_data:
            self.tool_id_entry.insert(0, str(initial_data.get("tool_id", "")))
            self.description_entry.insert(0, str(initial_data.get("description", "")))
            self.type_entry.insert(0, str(initial_data.get("type", "")))
            self.height_entry.insert(0, str(initial_data.get("height", "")))
            self.date_entry.insert(0, str(initial_data.get("last_sharpened", "")))
        
        # Configure column weights
        main_frame.columnconfigure(1, weight=1)
        
        # Buttons
        btn_frame = tk.Frame(main_frame)
        btn_frame.grid(row=5, column=0, columnspan=3, pady=20)
        
        save_btn = tk.Button(btn_frame, text="Save", command=self.save,
                            bg="#4CAF50", fg="white", width=10, font=("Arial", 10, "bold"))
        save_btn.pack(side="left", padx=5)
        
        cancel_btn = tk.Button(btn_frame, text="Cancel", command=self.cancel,
                              bg="#9E9E9E", fg="white", width=10, font=("Arial", 10, "bold"))
        cancel_btn.pack(side="left", padx=5)
        
        # Focus first entry
        self.tool_id_entry.focus()
        
        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self.save())
        self.dialog.bind('<Escape>', lambda e: self.cancel())
    
    def set_today_date(self):
        """Set today's date in the date field"""
        today = datetime.now().strftime("%Y-%m-%d")
        self.date_entry.delete(0, tk.END)
        self.date_entry.insert(0, today)
    
    def save(self):
        """Save the tool data"""
        # Validate required fields
        tool_id = self.tool_id_entry.get().strip()
        description = self.description_entry.get().strip()
        
        if not tool_id:
            messagebox.showerror("Validation Error", "Tool ID is required")
            self.tool_id_entry.focus()
            return
        
        if not description:
            messagebox.showerror("Validation Error", "Tool Description is required")
            self.description_entry.focus()
            return
        
        # Validate height if provided
        height_str = self.height_entry.get().strip()
        if height_str:
            try:
                float(height_str)
            except ValueError:
                messagebox.showerror("Validation Error", "Height must be a valid number")
                self.height_entry.focus()
                return
        
        self.result = {
            "tool_id": tool_id,
            "description": description,
            "type": self.type_entry.get().strip(),
            "height": height_str,
            "last_sharpened": self.date_entry.get().strip()
        }
        
        self.dialog.destroy()
    
    def cancel(self):
        """Cancel the dialog"""
        self.dialog.destroy()

class ChangePasswordDialog:
    """Dialog for changing user password"""

    def __init__(self, parent, username, hash_func):
        self.success = False
        self.new_password = None
        self.hash_func = hash_func

        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Change Password")
        self.dialog.geometry("350x220")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center the dialog
        parent.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 175
        y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 110
        self.dialog.geometry(f"+{x}+{y}")

        # Create form
        main_frame = tk.Frame(self.dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        tk.Label(main_frame, text=f"Change password for '{username}'", 
                font=("Arial", 12, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 15))

        tk.Label(main_frame, text="New Password:").grid(row=1, column=0, sticky="w", pady=5)
        self.new_pwd_entry = tk.Entry(main_frame, width=25, show="*")
        self.new_pwd_entry.grid(row=1, column=1, pady=5, padx=(10, 0))

        tk.Label(main_frame, text="Confirm Password:").grid(row=2, column=0, sticky="w", pady=5)
        self.confirm_entry = tk.Entry(main_frame, width=25, show="*")
        self.confirm_entry.grid(row=2, column=1, pady=5, padx=(10, 0))

        # Buttons
        btn_frame = tk.Frame(main_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)

        save_btn = tk.Button(btn_frame, text="Save", command=self.save,
                             bg="#4CAF50", fg="white", width=10)
        save_btn.pack(side="left", padx=5)

        cancel_btn = tk.Button(btn_frame, text="Cancel", command=self.cancel,
                               bg="#9E9E9E", fg="white", width=10)
        cancel_btn.pack(side="left", padx=5)

        # Focus first entry
        self.new_pwd_entry.focus()

        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self.save())
        self.dialog.bind('<Escape>', lambda e: self.cancel())

    def save(self):
        """Save the new password"""
        new_pwd = self.new_pwd_entry.get()
        confirm = self.confirm_entry.get()

        if not new_pwd or not confirm:
            messagebox.showerror("Validation Error", "Both fields are required")
            return

        if len(new_pwd) < 4:
            messagebox.showerror("Validation Error", "Password must be at least 4 characters")
            return

        if new_pwd != confirm:
            messagebox.showerror("Validation Error", "Passwords do not match")
            return

        self.new_password = new_pwd
        self.success = True
        self.dialog.destroy()

    def cancel(self):
        """Cancel the dialog"""
        self.dialog.destroy()

class MachineToolManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Machine Tool Management System")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Configuration
        self.machines = [
            "CNC Mill 001", "CNC Mill 002", "Lathe 001", "Lathe 002", 
            "Drill Press 001", "Grinder 001", "Bandsaw 001", "Press 001"
        ]
        
        self.current_user = None
        self.current_user_role = None
        self.current_machine = None
        self.data_folder = "machine_data"
        self.users_file = "users.json"
        
        # Create data folder if it doesn't exist
        if not os.path.exists(self.data_folder):
            os.makedirs(self.data_folder)
        
        # Initialize users system
        self.init_users_system()
        
        # Initialize the login screen
        self.show_login_screen()
    
    def init_users_system(self):
        """Initialize the user management system"""
        # Create default admin user if users file doesn't exist
        if not os.path.exists(self.users_file):
            default_users = {
                "admin": {
                    "password": self.hash_password("admin123"),
                    "role": "admin",
                    "created_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            }
            self.save_users(default_users)
    
    def hash_password(self, password):
        """Hash a password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def load_users(self):
        """Load users from JSON file"""
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Error loading users: {e}")
            return {}
    
    def save_users(self, users):
        """Save users to JSON file"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(users, f, indent=2)
        except Exception as e:
            print(f"Error saving users: {e}")
            messagebox.showerror("Error", f"Could not save user data: {e}")
    
    def clear_screen(self):
        """Clear all widgets from the root window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        """Display the login screen"""
        self.clear_screen()
        self.root.title("Login - Machine Tool Management")
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True)
        
        # Center the login form
        login_frame = tk.Frame(main_frame, bg="white", relief="raised", bd=2)
        login_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Add padding to login frame
        inner_frame = tk.Frame(login_frame, bg="white")
        inner_frame.pack(padx=40, pady=40)
        
        tk.Label(inner_frame, text="Machine Tool Management System", 
                font=("Arial", 18, "bold"), bg="white", fg="#333").pack(pady=(0, 30))
        
        # Username selection frame
        username_frame = tk.Frame(inner_frame, bg="white")
        username_frame.pack(pady=10)
        
        tk.Label(username_frame, text="Username:", font=("Arial", 12), bg="white").pack()
        
        # Create dropdown with all users
        users = self.load_users()
        user_list = list(users.keys()) if users else ["admin"]
        
        self.username_var = tk.StringVar()
        self.username_dropdown = ttk.Combobox(username_frame, textvariable=self.username_var, 
                                            values=user_list, width=20, state="readonly")
        self.username_dropdown.pack(pady=5)
        
        # Set default selection to first user (usually admin)
        if user_list:
            self.username_dropdown.set(user_list[0])
        
        # Manual entry option
        manual_frame = tk.Frame(inner_frame, bg="white")
        manual_frame.pack(pady=10)
        
        self.use_manual_var = tk.BooleanVar()
        manual_check = tk.Checkbutton(manual_frame, text="Enter username manually", 
                                     variable=self.use_manual_var, command=self.toggle_username_input,
                                     bg="white", font=("Arial", 10))
        manual_check.pack()
        
        self.username_entry = tk.Entry(manual_frame, width=22, font=("Arial", 10))
        # Initially hidden
        
        # Password frame
        password_frame = tk.Frame(inner_frame, bg="white")
        password_frame.pack(pady=10)
        
        tk.Label(password_frame, text="Password:", font=("Arial", 12), bg="white").pack()
        self.password_entry = tk.Entry(password_frame, width=22, show="*", font=("Arial", 10))
        self.password_entry.pack(pady=5)
        
        # Buttons frame
        button_frame = tk.Frame(inner_frame, bg="white")
        button_frame.pack(pady=20)
        
        # Login button
        login_btn = tk.Button(button_frame, text="Login", command=self.login, 
                             bg="#4CAF50", fg="white", width=15, font=("Arial", 11, "bold"))
        login_btn.pack(pady=5)
        
        # Register button
        register_btn = tk.Button(button_frame, text="Create Account", command=self.show_registration, 
                                bg="#2196F3", fg="white", width=15, font=("Arial", 11, "bold"))
        register_btn.pack(pady=5)
        
        # Refresh users button
        refresh_btn = tk.Button(button_frame, text="Refresh User List", command=self.refresh_user_dropdown, 
                               bg="#9E9E9E", fg="white", width=15, font=("Arial", 10))
        refresh_btn.pack(pady=5)
        
        # Admin note
        tk.Label(inner_frame, text="Default admin: username 'admin', password 'admin123'", 
                font=("Arial", 9), fg="gray", bg="white").pack(pady=20)
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda e: self.login())
        self.password_entry.focus()
    
    def show_registration(self):
        """Display the user registration screen"""
        self.clear_screen()
        self.root.title("Create Account - Machine Tool Management")
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True)
        
        # Center the registration form
        reg_frame = tk.Frame(main_frame, bg="white", relief="raised", bd=2)
        reg_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Add padding
        inner_frame = tk.Frame(reg_frame, bg="white")
        inner_frame.pack(padx=40, pady=40)
        
        tk.Label(inner_frame, text="Create New Account", 
                font=("Arial", 18, "bold"), bg="white", fg="#333").pack(pady=(0, 30))
        
        # Username
        tk.Label(inner_frame, text="Username:", font=("Arial", 12), bg="white").pack(pady=5)
        self.reg_username_entry = tk.Entry(inner_frame, width=25, font=("Arial", 10))
        self.reg_username_entry.pack(pady=5)
        
        # Password
        tk.Label(inner_frame, text="Password:", font=("Arial", 12), bg="white").pack(pady=5)
        self.reg_password_entry = tk.Entry(inner_frame, width=25, show="*", font=("Arial", 10))
        self.reg_password_entry.pack(pady=5)
        
        # Confirm Password
        tk.Label(inner_frame, text="Confirm Password:", font=("Arial", 12), bg="white").pack(pady=5)
        self.reg_confirm_entry = tk.Entry(inner_frame, width=25, show="*", font=("Arial", 10))
        self.reg_confirm_entry.pack(pady=5)
        
        # Role selection
        tk.Label(inner_frame, text="Role:", font=("Arial", 12), bg="white").pack(pady=(15, 5))
        self.role_var = tk.StringVar(value="operator")
        role_frame = tk.Frame(inner_frame, bg="white")
        role_frame.pack(pady=5)
        
        tk.Radiobutton(role_frame, text="Operator", variable=self.role_var, 
                      value="operator", bg="white", font=("Arial", 11)).pack(side="left", padx=10)
        tk.Radiobutton(role_frame, text="Manager", variable=self.role_var, 
                      value="manager", bg="white", font=("Arial", 11)).pack(side="left", padx=10)
        
        # Buttons
        btn_frame = tk.Frame(inner_frame, bg="white")
        btn_frame.pack(pady=30)
        
        create_btn = tk.Button(btn_frame, text="Create Account", command=self.create_account, 
                              bg="#4CAF50", fg="white", width=15, font=("Arial", 11, "bold"))
        create_btn.pack(side="left", padx=5)
        
        back_btn = tk.Button(btn_frame, text="Back to Login", command=self.show_login_screen, 
                            bg="#9E9E9E", fg="white", width=15, font=("Arial", 11, "bold"))
        back_btn.pack(side="left", padx=5)
        
        self.reg_username_entry.focus()
        
        # Bind Enter key
        self.root.bind('<Return>', lambda e: self.create_account())
    
    def create_account(self):
        """Create a new user account"""
        username = self.reg_username_entry.get().strip()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()
        role = self.role_var.get()
        
        # Validation
        if not username:
            messagebox.showerror("Error", "Username is required")
            self.reg_username_entry.focus()
            return
        
        if len(username) < 3:
            messagebox.showerror("Error", "Username must be at least 3 characters")
            self.reg_username_entry.focus()
            return
        
        if not password:
            messagebox.showerror("Error", "Password is required")
            self.reg_password_entry.focus()
            return
        
        if len(password) < 4:
            messagebox.showerror("Error", "Password must be at least 4 characters")
            self.reg_password_entry.focus()
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            self.reg_confirm_entry.focus()
            return
        
        # Check if username already exists
        users = self.load_users()
        if username.lower() in [u.lower() for u in users.keys()]:
            messagebox.showerror("Error", "Username already exists")
            self.reg_username_entry.focus()
            return
        
        # Create new user
        users[username] = {
            "password": self.hash_password(password),
            "role": role,
            "created_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.save_users(users)
        messagebox.showinfo("Success", f"Account created successfully!\nUsername: {username}\nRole: {role.title()}")
        self.show_login_screen()
    
    def toggle_username_input(self):
        """Toggle between dropdown and manual username entry"""
        if self.use_manual_var.get():
            self.username_dropdown.pack_forget()
            self.username_entry.pack(pady=5)
            self.username_entry.focus()
        else:
            self.username_entry.pack_forget()
            self.username_dropdown.pack(pady=5)
            self.password_entry.focus()
    
    def refresh_user_dropdown(self):
        """Refresh the user dropdown with current users"""
        users = self.load_users()
        user_list = list(users.keys()) if users else ["admin"]
        
        current_selection = self.username_var.get()
        self.username_dropdown['values'] = user_list
        
        # Keep current selection if it still exists, otherwise select first user
        if current_selection in user_list:
            self.username_dropdown.set(current_selection)
        elif user_list:
            self.username_dropdown.set(user_list[0])
        
        messagebox.showinfo("Refreshed", f"User list updated. Found {len(user_list)} users.")
    
    def login(self):
        """Handle user login"""
        # Get username from either dropdown or manual entry
        if self.use_manual_var.get():
            username = self.username_entry.get().strip()
        else:
            username = self.username_var.get()
        
        password = self.password_entry.get()
        
        if not username:
            messagebox.showerror("Login Failed", "Please select or enter a username")
            return
        
        if not password:
            messagebox.showerror("Login Failed", "Please enter a password")
            self.password_entry.focus()
            return
        
        users = self.load_users()
        
        if username in users:
            hashed_password = self.hash_password(password)
            if users[username]["password"] == hashed_password:
                self.current_user = username
                self.current_user_role = users[username]["role"]
                self.show_machine_selection()
            else:
                messagebox.showerror("Login Failed", "Invalid password")
                self.password_entry.delete(0, tk.END)
                self.password_entry.focus()
        else:
            messagebox.showerror("Login Failed", "Username not found")
            self.password_entry.delete(0, tk.END)
            self.password_entry.focus()
    
    def show_machine_selection(self):
        """Display the machine selection grid"""
        self.clear_screen()
        self.root.title(f"Machine Selection - Welcome {self.current_user}")
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(main_frame, bg="#f0f0f0")
        header_frame.pack(fill="x", pady=(0, 20))
        
        welcome_text = f"Welcome, {self.current_user}! ({self.current_user_role.title()})"
        tk.Label(header_frame, text=welcome_text, 
                font=("Arial", 16, "bold"), bg="#f0f0f0").pack(side="left")
        
        # Admin/Manager buttons
        button_frame = tk.Frame(header_frame, bg="#f0f0f0")
        button_frame.pack(side="right")
        
        if self.current_user_role in ["admin", "manager"]:
            user_mgmt_btn = tk.Button(button_frame, text="User Management", 
                                     command=self.show_user_management,
                                     bg="#FF9800", fg="white", font=("Arial", 10, "bold"))
            user_mgmt_btn.pack(side="left", padx=(0, 10))
        
        logout_btn = tk.Button(button_frame, text="Logout", command=self.logout,
                              bg="#f44336", fg="white", font=("Arial", 10, "bold"))
        logout_btn.pack(side="left")
        
        # Machine selection
        tk.Label(main_frame, text="Select a Machine:", 
                font=("Arial", 14, "bold"), bg="#f0f0f0").pack(pady=(0, 20))
        
        # Create grid of machine buttons
        machines_frame = tk.Frame(main_frame, bg="#f0f0f0")
        machines_frame.pack(expand=True, fill="both")
        
        cols = 3
        for i, machine in enumerate(self.machines):
            row = i // cols
            col = i % cols
            
            btn = tk.Button(machines_frame, text=machine, 
                           command=lambda m=machine: self.select_machine(m),
                           width=20, height=4, bg="#2196F3", fg="white",
                           font=("Arial", 12, "bold"), relief="raised", bd=3)
            btn.grid(row=row, column=col, padx=15, pady=15, sticky="nsew")
        
        # Configure grid weights for responsive layout
        for i in range(cols):
            machines_frame.columnconfigure(i, weight=1)
        for i in range((len(self.machines) + cols - 1) // cols):
            machines_frame.rowconfigure(i, weight=1)
    
    def show_user_management(self):
        """Display user management interface (Admin/Manager only)"""
        if self.current_user_role not in ["admin", "manager"]:
            messagebox.showerror("Access Denied", "You don't have permission to access user management")
            return
        
        self.clear_screen()
        self.root.title("User Management")
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(main_frame, bg="#f0f0f0")
        header_frame.pack(fill="x", pady=(0, 20))
        
        back_btn = tk.Button(header_frame, text="← Back", 
                            command=self.show_machine_selection,
                            bg="#9E9E9E", fg="white", font=("Arial", 11, "bold"))
        back_btn.pack(side="left")
        
        tk.Label(header_frame, text="User Management", 
                font=("Arial", 16, "bold"), bg="#f0f0f0").pack(side="left", padx=20)
        
        logout_btn = tk.Button(header_frame, text="Logout", command=self.logout,
                              bg="#f44336", fg="white", font=("Arial", 11, "bold"))
        logout_btn.pack(side="right")
        
        # User management buttons
        btn_frame = tk.Frame(main_frame, bg="#f0f0f0")
        btn_frame.pack(fill="x", pady=(0, 20))
        
        if self.current_user_role == "admin":
            delete_btn = tk.Button(btn_frame, text="Delete Selected User", 
                                  command=self.delete_selected_user,
                                  bg="#f44336", fg="white", font=("Arial", 10, "bold"))
            delete_btn.pack(side="left", padx=(0, 10))
            
            reset_pwd_btn = tk.Button(btn_frame, text="Reset Password", 
                                     command=self.reset_user_password,
                                     bg="#FF9800", fg="white", font=("Arial", 10, "bold"))
            reset_pwd_btn.pack(side="left", padx=(0, 10))
        
        change_pwd_btn = tk.Button(btn_frame, text="Change My Password", 
                                  command=self.change_my_password,
                                  bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        change_pwd_btn.pack(side="left")
        
        # User list table
        table_frame = tk.Frame(main_frame, bg="white", relief="sunken", bd=1)
        table_frame.pack(fill="both", expand=True)
        
        columns = ("username", "role", "created_date")
        self.user_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        self.user_tree.heading("username", text="Username")
        self.user_tree.heading("role", text="Role")
        self.user_tree.heading("created_date", text="Created Date")
        
        self.user_tree.column("username", width=200)
        self.user_tree.column("role", width=150)
        self.user_tree.column("created_date", width=200)
        
        # Add scrollbars
        user_v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.user_tree.yview)
        user_h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.user_tree.xview)
        self.user_tree.configure(yscrollcommand=user_v_scrollbar.set, xscrollcommand=user_h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.user_tree.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        user_v_scrollbar.grid(row=0, column=1, sticky="ns", pady=10)
        user_h_scrollbar.grid(row=1, column=0, sticky="ew", padx=10)
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Load user data
        self.refresh_user_table()
    
    def refresh_user_table(self):
        """Refresh the user management table"""
        # Clear existing items
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
        
        # Load and display users
        users = self.load_users()
        for username, user_data in users.items():
            self.user_tree.insert("", "end", values=(
                username,
                user_data.get("role", "").title(),
                user_data.get("created_date", "")
            ))
    
    def delete_selected_user(self):
        """Delete selected user (Admin only)"""
        if self.current_user_role != "admin":
            messagebox.showerror("Access Denied", "Only admins can delete users")
            return
        
        selection = self.user_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a user to delete")
            return
        
        item = selection[0]
        username = self.user_tree.item(item, "values")[0]
        
        if username == self.current_user:
            messagebox.showerror("Error", "You cannot delete your own account")
            return
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete user '{username}'?"):
            users = self.load_users()
            if username in users:
                del users[username]
                self.save_users(users)
                self.refresh_user_table()
                messagebox.showinfo("Success", f"User '{username}' has been deleted")
    
    def reset_user_password(self):
        """Reset password for selected user (Admin only)"""
        if self.current_user_role != "admin":
            messagebox.showerror("Access Denied", "Only admins can reset passwords")
            return
        
        selection = self.user_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a user to reset password")
            return
        
        item = selection[0]
        username = self.user_tree.item(item, "values")[0]
        
        new_password = simpledialog.askstring("Reset Password", 
                                             f"Enter new password for '{username}':",
                                             show='*')
        if new_password and len(new_password) >= 4:
            users = self.load_users()
            if username in users:
                users[username]["password"] = self.hash_password(new_password)
                self.save_users(users)
                messagebox.showinfo("Success", f"Password reset for '{username}'\nNew password: {new_password}")
        elif new_password:
            messagebox.showerror("Error", "Password must be at least 4 characters")
    
    def change_my_password(self):
        """Change current user's password"""
        dialog = ChangePasswordDialog(self.root, self.current_user, self.hash_password)
        self.root.wait_window(dialog.dialog)
        if dialog.success:
            users = self.load_users()
            users[self.current_user]["password"] = self.hash_password(dialog.new_password)
            self.save_users(users)
            messagebox.showinfo("Success", "Your password has been changed successfully")
    
    def select_machine(self, machine):
        """Handle machine selection and show tool table"""
        self.current_machine = machine
        self.show_tool_table()
    
    def get_machine_data_file(self):
        """Get the data file path for the current machine"""
        filename = f"{self.current_machine.replace(' ', '_').lower()}_tools.json"
        return os.path.join(self.data_folder, filename)
    
    def load_machine_data(self):
        """Load tool data for the current machine"""
        filepath = self.get_machine_data_file()
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
            except Exception as e:
                print(f"Error loading machine data: {e}")
                return []
        return []
    
    def save_machine_data(self, data):
        """Save tool data for the current machine"""
        filepath = self.get_machine_data_file()
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving machine data: {e}")
            messagebox.showerror("Error", f"Could not save machine data: {e}")
    
    def show_tool_table(self):
        """Display the tool management table for the selected machine"""
        self.clear_screen()
        self.root.title(f"Tool Management - {self.current_machine}")
        
        # Main container
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header with navigation
        header_frame = tk.Frame(main_frame, bg="#f0f0f0")
        header_frame.pack(fill="x", pady=(0, 20))
        
        back_btn = tk.Button(header_frame, text="← Back to Machines", 
                            command=self.show_machine_selection,
                            bg="#9E9E9E", fg="white", font=("Arial", 11, "bold"))
        back_btn.pack(side="left")
        
        tk.Label(header_frame, text=f"Tools for {self.current_machine}", 
                font=("Arial", 16, "bold"), bg="#f0f0f0").pack(side="left", padx=20)
        
        logout_btn = tk.Button(header_frame, text="Logout", command=self.logout,
                              bg="#f44336", fg="white", font=("Arial", 11, "bold"))
        logout_btn.pack(side="right")
        
        # Tool management buttons
        btn_frame = tk.Frame(main_frame, bg="#f0f0f0")
        btn_frame.pack(fill="x", pady=(0, 20))
        
        add_btn = tk.Button(btn_frame, text="Add New Tool", 
                           command=self.add_new_tool,
                           bg="#4CAF50", fg="white", font=("Arial", 11, "bold"))
        add_btn.pack(side="left", padx=(0, 10))
        
        edit_btn = tk.Button(btn_frame, text="Edit Selected", 
                            command=self.edit_selected_tool,
                            bg="#2196F3", fg="white", font=("Arial", 11, "bold"))
        edit_btn.pack(side="left", padx=(0, 10))
        
        delete_btn = tk.Button(btn_frame, text="Delete Selected", 
                              command=self.delete_selected_tool,
                              bg="#f44336", fg="white", font=("Arial", 11, "bold"))
        delete_btn.pack(side="left", padx=(0, 10))
        
        export_btn = tk.Button(btn_frame, text="Export Data", 
                              command=self.export_data,
                              bg="#FF9800", fg="white", font=("Arial", 11, "bold"))
        export_btn.pack(side="left")
        
        # Create treeview for tool table
        table_frame = tk.Frame(main_frame, bg="white", relief="sunken", bd=1)
        table_frame.pack(fill="both", expand=True)
        
        # Columns: Tool ID, Description, Type, Height, Last Sharpened
        columns = ("tool_id", "description", "type", "height", "last_sharpened")
        
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)
        
        # Define column headings and widths
        self.tree.heading("tool_id", text="Tool ID")
        self.tree.heading("description", text="Tool Description")
        self.tree.heading("type", text="Tool Type")
        self.tree.heading("height", text="Height (mm)")
        self.tree.heading("last_sharpened", text="Last Sharpened/Exchanged")
        
        self.tree.column("tool_id", width=100, anchor="center")
        self.tree.column("description", width=250)
        self.tree.column("type", width=150)
        self.tree.column("height", width=120, anchor="center")
        self.tree.column("last_sharpened", width=180, anchor="center")
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        v_scrollbar.grid(row=0, column=1, sticky="ns", pady=10)
        h_scrollbar.grid(row=1, column=0, sticky="ew", padx=10)
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Bind double-click to edit
        self.tree.bind("<Double-1>", lambda event: self.edit_selected_tool())
        
        # Status bar
        self.status_bar = tk.Label(self.root, text="Ready", relief="sunken", anchor="w", bg="lightgray")
        self.status_bar.pack(side="bottom", fill="x")
        
        # Load and display data
        self.refresh_table()
    
    def refresh_table(self):
        """Refresh the tool table with current data"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Load and display data
        data = self.load_machine_data()
        for tool in data:
            self.tree.insert("", "end", values=(
                tool.get("tool_id", ""),
                tool.get("description", ""),
                tool.get("type", ""),
                tool.get("height", ""),
                tool.get("last_sharpened", "")
            ))
        
        # Update status
        self.status_bar.config(text=f"Loaded {len(data)} tools for {self.current_machine}")
    
    def add_new_tool(self):
        """Add a new tool to the table"""
        dialog = ToolDialog(self.root, "Add New Tool")
        self.root.wait_window(dialog.dialog)
        if dialog.result:
            data = self.load_machine_data()
            
            # Check for duplicate tool ID
            existing_ids = [tool.get("tool_id", "").lower() for tool in data]
            if dialog.result["tool_id"].lower() in existing_ids:
                messagebox.showerror("Duplicate Tool ID", 
                                   f"Tool ID '{dialog.result['tool_id']}' already exists. Please use a different ID.")
                return
            
            data.append(dialog.result)
            self.save_machine_data(data)
            self.refresh_table()
            messagebox.showinfo("Success", f"Tool '{dialog.result['tool_id']}' added successfully!")
    
    def edit_selected_tool(self):
        """Edit the selected tool"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a tool to edit")
            return
        
        item = selection[0]
        values = self.tree.item(item, "values")
        
        # Create dialog with current values
        dialog = ToolDialog(self.root, "Edit Tool", {
            "tool_id": values[0],
            "description": values[1],
            "type": values[2],
            "height": values[3],
            "last_sharpened": values[4]
        })
        
        self.root.wait_window(dialog.dialog)
        if dialog.result:
            data = self.load_machine_data()
            # Find and update the tool
            for i, tool in enumerate(data):
                if (tool.get("tool_id", "") == values[0] and 
                    tool.get("description", "") == values[1]):
                    data[i] = dialog.result
                    break
            self.save_machine_data(data)
            self.refresh_table()
            messagebox.showinfo("Success", f"Tool '{dialog.result['tool_id']}' updated successfully!")
    
    def delete_selected_tool(self):
        """Delete the selected tool"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a tool to delete")
            return
        
        item = selection[0]
        values = self.tree.item(item, "values")
        tool_id = values[0]
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete tool '{tool_id}'?"):
            data = self.load_machine_data()
            # Remove the tool from data
            original_count = len(data)
            data = [tool for tool in data if not (
                tool.get("tool_id", "") == values[0] and 
                tool.get("description", "") == values[1]
            )]
            
            if len(data) < original_count:
                self.save_machine_data(data)
                self.refresh_table()
                messagebox.showinfo("Success", f"Tool '{tool_id}' deleted successfully!")
            else:
                messagebox.showerror("Error", "Could not find tool to delete")
    
    def export_data(self):
        """Export tool data to a readable format"""
        from tkinter import filedialog
        import csv
        
        data = self.load_machine_data()
        if not data:
            messagebox.showinfo("No Data", "No tool data to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Tool Data",
            initialname=f"{self.current_machine.replace(' ', '_').lower()}_tools"
        )
        
        if filename:
            try:
                if filename.lower().endswith('.csv'):
                    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                        fieldnames = ['tool_id', 'description', 'type', 'height', 'last_sharpened']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        for tool in data:
                            writer.writerow(tool)
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Success", f"Data exported successfully to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Could not export data: {e}")
    
    def logout(self):
        """Handle user logout"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.current_user = None
            self.current_user_role = None
            self.current_machine = None
            self.show_login_screen()
    
    def run(self):
        """Start the application"""
        try:
            # Set window icon if available
            # self.root.iconbitmap('icon.ico')  # Uncomment if you have an icon file
            pass
        except:
            pass
        
        # Center the window on screen
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        # Handle window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.root.mainloop()
    
    def on_closing(self):
        """Handle application closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
            self.root.destroy()


if __name__ == "__main__":
    try:
        app = MachineToolManager()
        app.run()
    except Exception as e:
        print(f"Error starting application: {e}")
        messagebox.showerror("Startup Error", f"Could not start application: {e}")