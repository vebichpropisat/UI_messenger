import os
from datetime import datetime
import pytz
import requests
from PyQt6 import QtWidgets, QtCore
from clientui import Ui_Messenger
from loginui import Ui_Login
from registerui import Ui_Register
from translate import Translator

# from dotenv import load_dotenv
#
# load_dotenv()

MESSENGER_HOST = os.getenv("MESSENGER_HOST") or "http://127.0.0.1:8000"


class User:
    def __init__(self, username, api_key=None):
        self.api_key = f"Token {api_key}"
        self.username = username


class Field:
    def __init__(self, data_type, required=False):
        self.__data_type = data_type
        self.__required = required

    @property
    def data_type(self):
        return self.__data_type

    @property
    def required(self):
        return self.__required


class Form:
    def __init__(self, data):
        self.__errors = []
        self.__validated_data = {}
        self.__validated = False
        self.__fields = None
        self.__validators = []
        fields = {}
        for attr_name in dir(self):
            if attr_name == "data":
                continue
            else:
                attr_ = getattr(self, attr_name)
                if isinstance(attr_, Field):
                    fields[attr_name] = attr_
        if not fields:
            raise Exception("Form requires atleast one Field")
        self.__fields = fields
        self.inputted_data = data

    def _validate(self):
        validated_data = {}
        for field_name, field in self.__fields.items():
            if field_name in validated_data:
                continue
            field_value = self.inputted_data.get(field_name)
            field_validator = getattr(self, f"validate_{field_name}", None)
            if field.required and not field_value:
                self.__errors.append("Заповніть всі поля")
                print(self.__errors)
            elif not isinstance(field_value, field.data_type):
                self.__errors.append(
                    f"Field {field_name} must be of type {field.data_type}"
                )
            else:
                is_valid, err = True, None
                if field_validator:
                    is_valid, err = field_validator()
                if not is_valid:
                    self.__errors.append(err)
                    continue
                validated_data[field_name] = field_value

        self.__validated = True
        if not self.errors:
            self.__validated_data = validated_data

    def is_valid(self):
        self._validate()
        return not self.__errors and self.__validated_data

    @property
    def data(self):
        if not self.__validated:
            raise Exception("Form was not validated. Call is_valid() first.")
        return self.__validated_data

    @property
    def errors(self):
        return self.__errors


class LoginForm(Form):
    username = Field(str, required=True)
    password = Field(str, required=True)


class RegisterForm(Form):
    username = Field(str, required=True)
    password = Field(str, required=True)
    password_2 = Field(str, required=True)

    def validate_password_2(self):
        if self.inputted_data.get("password") != self.inputted_data.get("password_2"):
            return False, f"Паролі не співпадають."
        return True, None


class Login(QtWidgets.QMainWindow, Ui_Login):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.lineEdit_2.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.register_window = Register()
        self._host = MESSENGER_HOST
        self.messanger_window = Messenger()

        self.pushButton_2.pressed.connect(self.register_window.show)
        self.pushButton_2.pressed.connect(self.hide)
        self.pushButton.pressed.connect(self.login)

    def _prepare_form_data(self):
        return {"username": self.lineEdit.text(), "password": self.lineEdit_2.text()}

    def login(self):
        form = LoginForm(self._prepare_form_data())
        if not form.is_valid():
            self.label_4.setText(
                QtCore.QCoreApplication.translate("Login", form.errors[0])
            )
            self.label_4.setStyleSheet("color: red")
            self.lineEdit.clear()
            self.lineEdit_2.clear()
        else:
            response = requests.post(self._host + "/auth/token/login", data=form.data)
            data = response.json()
            if "non_field_errors" in data:
                self.label_4.setText(
                    QtCore.QCoreApplication.translate(
                        "Login", "Ім`я або пароль були введені неправильно."
                    )
                )
                self.label_4.setStyleSheet("color: red")
                self.lineEdit.clear()
                self.lineEdit_2.clear()
            else:
                api_key = response.json()["auth_token"]
                print(api_key)
                self.messanger_window.user = User(
                    username=self.lineEdit.text(), api_key=api_key
                )
                self.messanger_window.label.setText(
                    QtCore.QCoreApplication.translate("Messenger", self.lineEdit.text())
                )
                self.messanger_window.show()
                self.hide()


class Register(QtWidgets.QMainWindow, Ui_Register):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.lineEdit_2.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.lineEdit_3.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self._host = MESSENGER_HOST
        self.messanger_window = Messenger()
        self.pushButton.pressed.connect(self.register)

    def _prepare_form_data(self):
        return {
            "username": self.lineEdit.text(),
            "password": self.lineEdit_2.text(),
            "password_2": self.lineEdit_3.text(),
        }

    def register(self):
        form = RegisterForm(self._prepare_form_data())
        if not form.is_valid():
            self.label_4.setText(
                QtCore.QCoreApplication.translate("Register", form.errors[0])
            )
            self.label_4.setStyleSheet("color: red")
            self.lineEdit.clear()
            self.lineEdit_2.clear()
            self.lineEdit_3.clear()
        else:
            response = requests.post(self._host + "/auth/users/", data=form.data)
            data = response.json()
            if "username" in data and response.status_code == 400:
                self.label_4.setText(
                    QtCore.QCoreApplication.translate(
                        "Register", "Користувач із таким ім`ям вже існує."
                    )
                )
                self.label_4.setStyleSheet("color: red")
                self.lineEdit.clear()
                self.lineEdit_2.clear()
                self.lineEdit_3.clear()
            elif "password" in data:
                psw_errors = response.json()["password"]
                print(psw_errors)
                self.label_4.setText(
                    QtCore.QCoreApplication.translate(
                        "Register",
                        Translator(to_lang="Ukrainian").translate(psw_errors[0]),
                    )
                )
                self.label_4.setStyleSheet("color: red")
                self.lineEdit.clear()
                self.lineEdit_2.clear()
                self.lineEdit_3.clear()
            else:
                response = requests.post(
                    self._host + "/auth/token/login", data=form.data
                )
                api_key = response.json()["auth_token"]
                self.messanger_window.user = User(
                    username=self.lineEdit.text(), api_key=api_key
                )
                self.messanger_window.label.setText(
                    QtCore.QCoreApplication.translate("Messenger", self.lineEdit.text())
                )
                self.messanger_window.show()
                self.hide()


class Messenger(QtWidgets.QMainWindow, Ui_Messenger):
    user = None

    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self._host = MESSENGER_HOST
        print(self._host)
        self.pushButton.pressed.connect(self.send_message)
        self.after = None
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.get_messages)
        self.timer.start(1000)

    def print_message(self, message):
        dt = message["created_at"]
        dt_str = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S.%fZ")
        tz = pytz.timezone("Etc/GMT-6")
        dt_str_utc3 = tz.normalize(dt_str.astimezone(tz))
        dt_str_utc3 = dt_str_utc3.strftime("%d %b %H:%M:%S")
        self.textBrowser.append(f"{dt_str_utc3} - {message['sender_name']}")
        self.textBrowser.append(message["text"])
        self.textBrowser.append("")

    def send_request(self, method, data=None, params=None):
        return requests.request(
            url=self._host + "/api/v1/messages/",
            method=method,
            data=data,
            params=params,
            headers={"Authorization": self.user.api_key},
        )

    def _post(self, data):
        return self.send_request(method="POST", data=data)

    def _get(self, params):
        return self.send_request(method="GET", params=params)

    def get_messages(self):
        try:
            response = self._get(params={"after": self.after})
        except Exception as e:
            print(e)
            return
        if response.status_code != 200:
            print(f"BAD RESPONSE {response.status_code}")
            print(response)
            return
        print(response.json())
        messages = response.json()
        for message in messages:
            print(message)
            self.print_message(message)
            self.after = message["created_at"]

    def send_message(self):
        text = self.textEdit.toPlainText()
        try:
            response = self._post(data={"text": text})
        except Exception as e:
            print(e)
            self.textBrowser.append("Сервер недоступен")
            self.textBrowser.append("Попробуйте еще раз")
            self.textBrowser.append("")
            return
        if response.status_code != 200:
            print(response.json())
            self.textBrowser.append(
                "Имя и текст не должны быть пустыми. Текст не должен привышать 1000 символов."
            )
            self.textBrowser.append("")
            return

        self.textEdit.clear()


app = QtWidgets.QApplication([])
window = Login()
window.show()
app.exec()

# def main():
#     window = Login()
#     window.show()
#     app.exec()
