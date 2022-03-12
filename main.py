from tkinter import*
from cryptography.fernet import Fernet, InvalidToken
from tkinter import messagebox
import os

with open("class.txt", "a+") as file:
    if os.path.getsize("class.txt")==0:
        key = Fernet.generate_key()
        file.write(key.decode())

with open ("class.txt", "r") as filename:
    a = filename.read()
    fernet = Fernet(a.encode())
    

def encryption():
    global fernet
    def encrypt():
        global fernet
        def save():
            with open('encrypted_passwords.txt', "a") as pwd:
                pwd.write(f"{str1.get()} | {str2.get()} | {enc_pwd.decode('utf-8')}\n")
                messagebox.showinfo("Done", f"Password added successfully to {os.getcwd()}")

        
        enc_pwd = fernet.encrypt(str3.get().encode())
        #3
        root = Toplevel()
        root.resizable(0,0)
        root.configure(bg="thistle2")
        Label(root, text=f"for username : {str2.get()}", pady=8, padx=8, fg='purple4', font="verdana 15",bg='thistle2').pack()
        Label(root, text=f"encrypted password is : {enc_pwd.decode('utf-8')}", pady=8, padx=8, fg='purple4', font="verdana 10",bg='thistle2').pack()
        Button(root, text="Save", command=save, font="lucida 10 bold", bd=5, bg="plum1", padx=8, pady=12).pack(fill=X)
        Button(root, text="Exit", command=exit, font="lucida 10 bold", bd=5, bg="plum1", padx=8, pady=12).pack(fill=X)
        #################################################

    #2
    top=Toplevel()
    top.configure(bg='thistle2')
    top.resizable(0,0)
    str1 = StringVar()
    str2 = StringVar()
    str3 = StringVar()
    Label(top, text="Encryption", pady=8, padx=8, fg='purple4', font="verdana 30",bg='thistle2').grid(row=0, column=1)
    Label(top, text="Distraction: ", fg='purple3', font="verdana 24",bg='thistle2', padx=8, pady=8).grid(row=1, column=0)
    Entry(top, textvariable=str1, bd=5, bg='mediumpurple1', font="verdana 15").grid(row=1, column=1)
    Label(top, text="Username: ", fg='purple3', font="verdana 24",bg='thistle2', padx=8, pady=8).grid(row=2, column=0)
    Entry(top, textvariable=str2, bd=5, bg='mediumpurple1', font="verdana 15").grid(row=2, column=1)
    Label(top, text="Password: ", fg='purple3', font="verdana 24",bg='thistle2', padx=8, pady=8).grid(row=3, column=0)
    Entry(top, textvariable=str3, bd=5, bg='mediumpurple1', font="verdana 15").grid(row=3, column=1)
    Button(top, text="Encrypt", font="lucida 15 bold", bd=10, bg="mediumorchid1",command=encrypt, padx=8, pady=8).grid(row=4, columnspan=5)
    ####################################



def decryption():
    global fernet
    def decrypt():
        global fernet
        try:
            dec_pwd = fernet.decrypt(str4.get().encode())
            #5
            messagebox.showinfo("Decrypted Password", f"Decrypted Password : {dec_pwd.decode()}")
            ############################
        except InvalidToken:
            messagebox.showerror("Invalid Password", "The encrypted password that you have entered in not on your list, add the password and then try again later")
    
    #4
    root = Toplevel()
    root.configure(bg="thistle2")
    root.resizable(0,0)
    str4 = StringVar()
    Label(root, text="Decryption", pady=8, padx=8, fg='purple4', font="verdana 30",bg='thistle2').grid(row=0, column=1)
    Label(root, text="Enter Password: ", fg='purple3', font="verdana 24",bg='thistle2', padx=8, pady=8).grid(row=1, column=0)
    Entry(root, textvariable=str4, bd=5, bg='mediumpurple1', font="verdana 15", width=70).grid(row=1, column=1)
    Button(root, text="Decrypt", command=decrypt, font="lucida 15 bold", bd=10, bg="mediumorchid1", padx=8, pady=8).grid(row=2, column=1)
    #########################################################



windows = Tk()
windows.title("Password Encrypter")
windows.configure(bg="thistle2")
windows.resizable(0,0)
#main window
btn_encrypted = Button(windows, text="Encryption", font="lucida 30 bold", bd=10, bg="mediumorchid1", command=encryption)
btn_encrypted.pack(fill=X, pady=16)
btn_decrypted = Button(windows, text="Decryption", font="lucida 30 bold", bd=10, bg="mediumorchid1", command=decryption)
btn_decrypted.pack(fill=X, pady=16)
#######################################################
windows.mainloop()