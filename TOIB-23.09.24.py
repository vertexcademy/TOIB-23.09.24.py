# Напишите программу на Python, которая определяет функцию хэширования, принимает строку пароля в качестве входных данных и возвращает ее хешированное представление SHA-256 в виде шестнадцатеричной
# строки (import hashlib).

# Практическая работа 1 по дисциплине - "ТЕХНОЛОГИИ ОБЕСПЕЧЕНИЯ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ"
import hashlib
from tkinter import Tk, label, Frame

# Функция для получения SHA-256 хеша от строки пароля
def get_sha256_hash(password: str) -> str:
    sha256 = hashlib.sha256()  
    sha256.update(password.encode('utf-8')) 
    return sha256.hexdigest() 

# Функция для отображения хеша пароля
def show_hash():
    password = entry.get()  
    if password:   
        hashed_password = get_sha256_hash(password)  
        result_var.set(hashed_password) 
    else:
        result_var.set("Пароль не был введен")  

# Функция для переключения введенного пароля
def password_visibility():
    if entry.cget('show') == '*':  
        entry.config(show='')  
        toggle_button.config(text='Скрыть')  
    else:
        entry.config(show='*') 
        toggle_button.config(text='Показать') 

# Главное окно Tkinter
root = Tk()  
root.title("SHA-256 хеширование пароля")  

# Создаем метку и поле для ввода пароля
prompt_label = Label(root, text="Введите пароль для хеширования:")  
prompt_label.pack(pady=5)  

# Размещаем поле ввода и кнопку скрытия пароля
password_frame = Frame(root)  
password_frame.pack(pady=5)  
entry = Entry(password_frame, show='*')  
entry.pack(side='left')  
toggle_button = Button(password_frame, text='Показать', command=password_visibility)  
toggle_button.pack(side='left')  

# Кнопка для запуска функции хеширования
hash_button = Button(root, text="Хешировать", command=show_hash)  
hash_button.pack(pady=5)  

# Поле для копирования хэша
result_var = StringVar()  
result_entry = Entry(root, textvariable=result_var, state='readonly', width=70)  

# Запускаем главный цикл Tkinter
root.mainloop() # запускаем цикл