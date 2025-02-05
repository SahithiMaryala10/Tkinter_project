import tkinter as tk
from tkinter import ttk 
import logging
import re
import os
import random
import smtplib
from email.message import EmailMessage 
from tkinter import simpledialog, messagebox

# Configure logging
logging.basicConfig(filename='username_validation.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#username validation
def validate_username(username):
    if len(username) <= 5:
        logging.error("Username should be at least 5 characters long.")
        print("Username should be at least 5 characters long.")
        s_username("Username should be at least 5 characters long.","red")
        return False
    if len(username) > 20:
        logging.error("Username should not exceed 20 characters.")
        print("Username should not exceed 20 characters.")
        s_username("Username should not exceed 20 characters.",'red')
        return False
    if not username.isalnum():
        logging.error("Username should contain only alphanumeric characters.")
        print("Username should contain only alphanumeric characters.")
        s_username("Username should contain only alphanumeric characters.",'red')
        return False
    logging.info("Username '{}' is valid.".format(username))
    print("valid username")
    s_username("valid username",'green')
    return True

#password validation
def validate_password(password):
    if not password:
        logging.error("password cannot be empty.")
        print("password cannot be empty.")
        s_password("Password cannot be empty.",'red') 
        return False
    if len(password) < 8:
        logging.error("Password must be at least 8 characters long.")
        print("Password must be at least 8 characters long.")
        s_password("Password must be at least 8 characters long",'red') 
        return False
    if not any(c.isupper() for c in password):
        logging.error("Password must contain at least one uppercase letter.")
        print("Password must contain at least one uppercase letter.")
        s_password("Password must contain at least one uppercase letter.",'red')
        return False
    if not any(c.islower() for c in password):
        logging.error("Password must contain at least one lowercase letter.")
        print("Password must contain at least one lowercase letter.")
        s_password("Password must contain at least one lowercase letter.",'red')
        return False
    if not any(c.isdigit() for c in password):
        logging.error("Password must contain at least one digit.")
        print("Password must contain at least one digit.")
        s_password("Password must contain at least one digit.",'red') 
        return False
    if not any(c in "!@#$%^&*()-_=+" for c in password):
        logging.error("Password must contain at least one special character.")
        print("Password must contain at least one special character.")
        s_password("Password must contain at least one special character.",'red') 
        return False
    logging.info("Password is valid.")
    print("Password is valid.")
    s_password("Password is valid.", 'green') 
    return True

#re_pwd validation
def validate_repswd(re_enter_pwd, password):
        if not re_enter_pwd:
            logging.error("Field cannot be empty")
            print("Field cannot be empty")
            s_repwd("Field cannot be empty","red")
            return False
        if password != re_enter_pwd:
            logging.error("Passwords did not match.")
            print("Passwords did not match.")
            s_repwd("Passwords did not match.","red")
            return False
        logging.info("Passwords matched.")
        s_repwd("Passwords matched.",'green')
        print("matched")
        return True

#check email is valid and exist or not
def validate_email(email):
    try:
        if not email:
            logging.error("Email cannot be empty.")
            s_success_label("Email cannot be empty",'red')
            print("Email cannot be empty.")
            return False
        if not email.endswith("@gmail.com"):
            logging.error("Email is not a valid Gmail address.")
            s_success_label("Email is not valid",'red')
            print("Email is not a valid Gmail address.")
            return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            print("Invalid email format.")
            s_success_label("Invalid email format",'red')
            logging.error("Invalid email format.")
            return False
        try:
            with open('registrations.txt', "r") as file:
                    lines =  file.readlines()
                    for line in lines:
                        if line.startswith('Email:'):
                            e_email = line.strip().split(':')[1].strip()
                            if email == e_email:
                                print(f'Email already exists - {email}')
                                s_success_label("Email already exists",'red')
                                return False
        except FileNotFoundError:
            logging.error("Error: File not found.")
            print("Error: File not found.")
            return False
        logging.info("Email is valid.")
        print("valid")
        s_success_label("valid email","green")
        return True
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        print(f"An error occurred: {str(e)}")
        return False

#function to validate all fields and send otp
def validate_and_send_otp(username, password, Re_enter_pwd, email):
    if not validate_username(username) or not validate_password(password) or not validate_repswd(Re_enter_pwd, password) or not validate_email(email):
        logging.error("Registration failed. Please check the log file for details.")
        print("Invalid entries")
        return None
    else:
        otp = ''.join(str(random.randint(0, 9)) for _ in range(6))
        print('OTP is:', otp)
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        from_email = 'sahithigupta06@gmail.com'
        server.login(from_email, 'pbrd foom nbbz qtyv')
        to_mail = email 
        msg = EmailMessage()
        msg['subject'] = 'OTP Verification'
        msg['from'] = from_email
        msg['to'] = to_mail
        msg.set_content(f'Your OTP is :  {otp}')
        server.send_message(msg)
        print(f'Sent to {to_mail}')
        print("OTP sent successfully.")
        s_success_label("OTP sent successfully.",'green')
        return otp
    except Exception as e:
        logging.error(f"Failed to send OTP: {e}")
        s_email_otp("Failed to send OTP.",'red')
        return None

#function to clear registration page fields
def clear_fields():
    uname_entry.delete(0, tk.END)
    Password_entry.delete(0, tk.END)
    Re_pwd_entry.delete(0, tk.END)
    Email_entry.delete(0, tk.END)
    Otp_entry.delete(0, tk.END)
    uname_label.config(text=" ")
    password_label.config(text=" ")
    repwd_label.config(text=" ")
    otp_label.config(text=" ")
    success_label.config(text=" ")

#function to clear login page fields
def clear_all():
    l_email_entry.delete(0,tk.END)
    Pwd_entry.delete(0,tk.END)
    l_success_label.config(text=" ")

# Login function
def login():
    l_email = l_email_entry.get()
    l_password = Pwd_entry.get()
    try:
        folder_path = "user_data"
        file_name = os.path.join(folder_path, f"{l_email}.txt") 
        with open(file_name, "r") as file:
            lines = file.readlines()
            stored_email = lines[2].strip().split(': ')[1]
            stored_password = lines[1].strip().split(': ')[1]
            if stored_email == l_email and stored_password == l_password:
                logging.info("Login successful")
                login_success_label("Login successful",'green')
                return True  
            else:
                return False  
    except FileNotFoundError:
        logging.error("Not a registered user")
        login_success_label("Not a registered user",'red')
        return False
    except Exception as e:
        logging.error("An error occurred while checking login")
        print("An error occurred while checking login:", str(e))
        return False 

#function for labels
def s_username(message,color):
    uname_label.config(text=message, foreground=color)
def s_password(message,color):
    password_label.config(text=message, foreground=color)
def s_repwd(message,color):
    repwd_label.config(text=message, foreground=color)
#def s_email(message,color):
    #email_label.config(text=message,foreground=color)
def s_email_otp(message,color):
    otp_label.config(text=message, foreground=color)
def s_success_label(message, color):
    success_label.config(text=message,foreground=color)
def login_success_label(message,color):
    l_success_label.config(text=message,foreground=color)

#get inputs 
def get_reg_inputs():
    global username, password, re_enter_pwd, email,otp
    username = uname_entry.get()
    password = Password_entry.get()
    re_enter_pwd = Re_pwd_entry.get()
    email = Email_entry.get()
    otp=Otp_entry.get()
    otp = validate_and_send_otp(username, password, re_enter_pwd, email)

# Function to register user and load into file
def register():
    global username, password, re_enter_pwd, email
    if otp == Otp_entry.get():
        try:
            folder_path = "user_data"
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
            file_name = os.path.join(folder_path, f"{email}.txt")
            with open(file_name, 'w') as f:
                f.write(f'Username: {username}\n')
                f.write(f'Password: {password}\n')
                f.write(f'Email: {email}\n')
            print("Registration successful")
            s_success_label('REGISTRATION SUCCESSFUL', 'green')
        except Exception as e:
            print('Failed to register', str(e))
            s_success_label('Failed to register', 'red')
    else:
        s_success_label('OTP not Matched', 'red')
        print("OTP not matched")

#function to validate current password in reset window
def validate_current_password(email, current_password):
    try:
        folder_path = "user_data"
        file_name = os.path.join(folder_path, f"{email}.txt")
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                lines = file.readlines()
                registered_password = lines[1].strip().split(': ')[1]
                if current_password == registered_password:
                    return True
                else:
                    return False
        else:
            return False
    except Exception as e:
        logging.error("An error occurred while validating current password:", str(e))
        return False

root = tk.Tk()
root.title("Login and Registration")
root.geometry("400x300")

#creating tabbed widgets
tabs = ttk.Notebook(root)
tabs.pack(fill="both", expand=True)

# Login tab
login_tab = ttk.Frame(tabs)
tabs.add(login_tab, text="Login")
login_frame = ttk.Frame(login_tab)
login_frame.pack()
register_tab = ttk.Frame(tabs)
tabs.add(register_tab, text="Register")
register_frame = ttk.Frame(register_tab)
register_frame.pack()

# Create a style object
style = ttk.Style()

# Configure the style for the tabs
style.configure('TNotebook.Tab', font=('Arial', 14), background='lightgray', foreground='black')

# Set padding for the tabs
style.layout('TNotebook.Tab', [('Notebook.tab', {'sticky': 'nswe', 'children':
            [('Notebook.padding', {'side': 'top', 'sticky': 'nswe', 'children':
                [('Notebook.focus', {'side': 'top', 'sticky': 'nswe', 'children':
                    [('Notebook.label', {'side': 'top', 'sticky': ''})],
                })]})]})])

#Registration entry fields
uname_entry = ttk.Entry(register_frame,font=("arial",14))
Password_entry = ttk.Entry(register_frame, show="*",font=("arial",14))
Re_pwd_entry = ttk.Entry(register_frame, show="*",font=("arial",14))
Email_entry = ttk.Entry(register_frame,font=("arial",14))
Otp_entry = ttk.Entry(register_frame,font=("arial",14))

# Register tab
ttk.Label(register_frame, text="Username",font=('Arial', 14)).grid(column=0, row=0, padx=10, pady=10, sticky="e")
uname_label=ttk.Label(register_frame,text=" ",foreground='red')
uname_label.grid(row=0, column=2, padx=10, pady=10)
ttk.Label(register_frame, text="Password",font=('Arial', 14)).grid(column=0, row=1, padx=10, pady=10, sticky="e")
password_label=ttk.Label(register_frame,text=" ",foreground='red')
password_label.grid(row=1, column=2, padx=10, pady=10)
ttk.Label(register_frame, text="Re-enter Password",font=('Arial', 14)).grid(column=0, row=2, padx=10, pady=10, sticky="e")
repwd_label=ttk.Label(register_frame,text=" ",foreground='red')
repwd_label.grid(row=2, column=2, padx=10, pady=10)
ttk.Label(register_frame, text="Email",font=('Arial', 14)).grid(column=0, row=3, padx=10, pady=10, sticky="e")
ttk.Button(register_frame, text="Send OTP", command=get_reg_inputs,style="Send.TButton").grid(column=2, row=3, padx=10, pady=10)
ttk.Label(register_frame, text="OTP",font=('Arial', 14)).grid(column=0, row=4, padx=10, pady=10, sticky="e")
otp_label=ttk.Label(register_frame,text=" ",foreground='red')
otp_label.grid(row=4, column=2, padx=10, pady=10)
ttk.Button(register_frame, text="Register",command=register,style='Send.TButton').grid(column=0, row=5, padx=10, pady=10)
ttk.Button(register_frame, text="Clear",command=clear_fields,style="Send.TButton").grid(column=1, row=5, padx=10, pady=10)
success_label = ttk.Label(register_frame, text='', foreground='green')
success_label.grid(row=6, column=1, padx=10, pady=10)

#buton styling
style=ttk.Style()
style.configure("Send.TButton",font=(None,14),foreground="black")    
  
#aligning the widgets
uname_entry.grid(column=1, row=0, padx=10, pady=10, sticky="w")
Password_entry.grid(column=1, row=1, padx=10, pady=10, sticky="w")
Re_pwd_entry.grid(column=1, row=2, padx=10, pady=10, sticky="w")
Email_entry.grid(column=1, row=3, padx=10, pady=10, sticky="w")
Otp_entry.grid(column=1, row=4, padx=10, pady=10, sticky="w")

# Login tab
ttk.Label(login_frame, text="Email",font=('Arial', 14)).grid(column=0, row=0, padx=10, pady=10, sticky="e")
ttk.Label(login_frame, text="Password",font=('Arial', 14)).grid(column=0, row=1, padx=10, pady=10, sticky="e")
ttk.Button(login_frame, text="Login",command=login,style="Send.TButton").grid(column=1, row=2, padx=10, pady=10)
ttk.Button(login_frame, text="Clear",command=clear_all,style="Send.TButton").grid(column=2, row=2, padx=10, pady=10)
l_success_label = ttk.Label(login_frame, text='', foreground='green')
l_success_label.grid(row=3, column=1, padx=10, pady=10)

# Add "Forgot Password" label in the login frame
forgot_password_label = ttk.Label(login_frame, text="Forgot Password?", font=('Arial', 12), foreground='blue')
forgot_password_label.grid(row=2, column=0, padx=10, pady=10)
forgot_password_label.bind("<Button-1>", lambda event: forgot_password_window())

#entering login values
l_email_entry = ttk.Entry(login_frame,font=("arial",14)) 
Pwd_entry = ttk.Entry(login_frame, show="*",font=("arial",14))

#aligning login widgets
l_email_entry.grid(column=1, row=0, padx=10, pady=10, sticky="w")
Pwd_entry.grid(column=1, row=1, padx=10, pady=10, sticky="w")

#function to get reset password window
def reset_password():
    email = email_entry.get()
    current_password = current_password_entry.get()
    new_password = new_password_entry.get()
    try:  
        if not current_password:
            messagebox.showerror("Error", "Please enter your current password.")
            return
        if not new_password:
            messagebox.showerror("Error", "Please enter a new password.")
            return
        folder_path = "user_data"
        file_name = os.path.join(folder_path, f"{email}.txt")
        if os.path.exists(file_name):
            if validate_current_password(email, current_password):
                if validate_password(new_password):
                    with open(file_name, 'r+') as file:
                        lines = file.readlines()
                        lines[1] = f'Password: {new_password}\n'  
                        file.seek(0)
                        file.writelines(lines)
                    messagebox.showinfo("Password Reset", "Your password has been successfully reset.")
                    # window.destroy()
                    logging.info("Password reset successfully for email: %s", email)
                else:
                    messagebox.showerror("Error", "Please enter a valid password. Password should be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
                    logging.error("Invalid password format for email: %s", email)
            else:
                messagebox.showerror("Error", "Incorrect current password.")
        else:
            messagebox.showerror("Error", "Email address not found.")
            logging.error("Email address not found: %s", email)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
        logging.error("An error occurred during password reset: %s", str(e))

def forgot_password_window():
    reset_password_window = tk.Toplevel(root)
    reset_password_window.title("Reset Password")
    reset_password_window.geometry("300x200")
    email_label = ttk.Label(reset_password_window, text="Enter your email:", font=('Arial', 12))
    email_label.pack(pady=10)
    global email_entry
    email_entry = ttk.Entry(reset_password_window, font=("Arial", 12))
    email_entry.pack(pady=5)
    password_label = ttk.Label(reset_password_window, text="Enter current password:", font=('Arial', 12))
    password_label.pack(pady=5)
    global current_password_entry
    current_password_entry = ttk.Entry(reset_password_window, show="*", font=("Arial", 12))
    current_password_entry.pack(pady=5)
    new_password_label = ttk.Label(reset_password_window, text="Enter new password:", font=('Arial', 12))
    new_password_label.pack(pady=5)
    global new_password_entry
    new_password_entry = ttk.Entry(reset_password_window, show="*", font=("Arial", 12))
    new_password_entry.pack(pady=5)
    reset_button = ttk.Button(reset_password_window, text="Reset Password", command=reset_password,style="Send.TButton")
    reset_button.pack(pady=10)
    
root.mainloop()   

