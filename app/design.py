import os
import sys
import logic

from PyQt5.QtGui import QTextOption
from PyQt5.QtWidgets import QApplication, QMainWindow, QListWidget, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, \
    QLabel, QRadioButton, QLineEdit, QFormLayout, QDialog, QFileDialog, QListWidgetItem, QTableWidgetItem, QTableWidget, \
    QScrollBar, QTextEdit, QCheckBox, QComboBox
from PyQt5.QtCore import Qt, QVariant
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class MainWindow(QMainWindow):
    privateRings = []
    publicRings = []
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PGP SIMULATION")
        self.setGeometry(600, 200, 600, 400)

        # Kreiranje centralnog widgeta i glavnog layout-a
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        top_layout = QHBoxLayout()
        main_layout.addLayout(top_layout)

        # Kreiranje prve liste
        list1_layout = QVBoxLayout()
        top_layout.addLayout(list1_layout)
        list1_layout.addWidget(QLabel("PRIVATE KEY RING"))
        self.list_widget_1 = QListWidget()
        self.list_widget_1.setFixedWidth(250)
        list1_layout.addWidget(self.list_widget_1)
        self.list_widget_1.itemDoubleClicked.connect(self.details_private_key)

        # Dodavanje dugmica za detalje i brisanje
        button_layout = QHBoxLayout()
        list1_layout.addLayout(button_layout)
        button_layout.addStretch(1)

        details_private_button = QPushButton("Details")
        details_private_button.clicked.connect(self.details_private_key)
        button_layout.addWidget(details_private_button)
        button_layout.addSpacing(10)

        delete_private_button = QPushButton("Remove")
        delete_private_button.clicked.connect(self.delete_private_key)
        button_layout.addWidget(delete_private_button)
        button_layout.addStretch(1)

        # Kreiranje vertikalnog layout-a za dugmad u sredini
        middle_buttons_layout = QVBoxLayout()
        middle_buttons_layout.addSpacing(50)
        new_key_button = QPushButton("New key")
        new_key_button.clicked.connect(self.open_new_key_window)
        middle_buttons_layout.addWidget(new_key_button)
        middle_buttons_layout.addSpacing(20)

        import_button = QPushButton("Import")
        import_button.clicked.connect(self.import_key)
        middle_buttons_layout.addWidget(import_button)
        middle_buttons_layout.addSpacing(20)

        export_priv_button = QPushButton("Export private")
        export_priv_button.clicked.connect(self.export_private_key)
        middle_buttons_layout.addWidget(export_priv_button)
        middle_buttons_layout.addSpacing(20)

        export_pub_button = QPushButton("Export public")
        export_pub_button.clicked.connect(self.export_public_key)
        middle_buttons_layout.addWidget(export_pub_button)
        middle_buttons_layout.addStretch(1)
        middle_buttons_layout.addSpacing(50)
        top_layout.addLayout(middle_buttons_layout)

        # Kreiranje druge liste
        list2_layout = QVBoxLayout()
        top_layout.addLayout(list2_layout)
        list2_layout.addWidget(QLabel("PUBLIC KEY RING"))
        self.list_widget_2 = QListWidget()
        self.list_widget_2.setFixedWidth(250)
        list2_layout.addWidget(self.list_widget_2)
        self.list_widget_2.itemDoubleClicked.connect(self.details_public_key)

        # Dodavanje dugmica za detalje i brisanje
        button_layout2 = QHBoxLayout()
        list2_layout.addLayout(button_layout2)
        button_layout2.addStretch(1)

        details_public_button = QPushButton("Details")
        details_public_button.clicked.connect(self.details_public_key)
        button_layout2.addWidget(details_public_button)
        button_layout2.addSpacing(10)

        delete_public_button = QPushButton("Remove")
        delete_public_button.clicked.connect(self.delete_public_key)
        button_layout2.addWidget(delete_public_button)
        button_layout2.addStretch(1)

        # Kreiranje horizontalnog layout-a za dugmad ispod
        bottom_layout = QHBoxLayout()
        main_layout.addSpacing(75)
        main_layout.addLayout(bottom_layout)
        bottom_layout.setContentsMargins(0, 0, 0, 75)

        left_button = QPushButton("SEND")
        left_button.setFixedSize(100, 100)
        left_button.clicked.connect(self.show_send)
        bottom_layout.addWidget(left_button)

        right_button = QPushButton("RECEIVE")
        right_button.setFixedSize(100, 100)
        right_button.clicked.connect(self.show_receive)
        bottom_layout.addWidget(right_button)
        main_layout.addStretch(1)

    def open_new_key_window(self):
        dialog = NewKeyDialog(self)
        dialog.exec_()

    def show_send(self):
        dialog = SendDialog(self)
        dialog.exec_()

    def show_receive(self):
        dialog = ReceiveDialog(self)
        dialog.exec_()

    def add_private_key(self, private_key: logic.PrivateKeyRing):
        self.privateRings.append(private_key)
        item1 = QListWidgetItem(private_key.email + "->" + private_key.name)
        item1.setData(Qt.UserRole, QVariant(private_key.keyID))
        self.list_widget_1.addItem(item1)

    def add_public_key(self, public_key: logic.PublicKeyRing):
        self.publicRings.append(public_key)
        item1 = QListWidgetItem(public_key.email + "->" + public_key.name)
        item1.setData(Qt.UserRole, QVariant(public_key.keyID))
        self.list_widget_2.addItem(item1)

    def delete_private_key(self):
        selected_items = self.list_widget_1.selectedItems()
        if not selected_items:
            return
        for i in self.privateRings:
            if i.keyID == selected_items[0].data(Qt.UserRole):
                self.privateRings.remove(i)
                break
        self.list_widget_1.takeItem(self.list_widget_1.row(selected_items[0]))

    def delete_public_key(self):
        selected_items = self.list_widget_2.selectedItems()
        if not selected_items:
            return
        for i in self.privateRings:
            if i.keyID == selected_items[0].data(Qt.UserRole):
                self.publicRings.remove(i)
                break
        self.list_widget_2.takeItem(self.list_widget_2.row(selected_items[0]))

    def import_key(self):
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("PEM Files (*.pem)")
        file_dialog.setWindowTitle("Select .pem File")

        if file_dialog.exec_() == QFileDialog.Accepted:
            file_path = file_dialog.selectedFiles()[0]
            with open(file_path, 'rb') as key_file:
                key_data = key_file.read()
                try:
                    private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
                    dialog = ImportKeyDialog(self)
                    if dialog.exec_() == QDialog.Accepted:
                        email = dialog.email_input.text()
                        name = dialog.name_input.text()
                        password = dialog.password_input.text()
                    key_ring = logic.PrivateKeyRing(name,email,private_key)
                    self.add_private_key(key_ring)
                    return private_key
                except ValueError:
                    pass

                try:
                    public_key = serialization.load_pem_public_key(key_data, backend=default_backend())
                    dialog = ImportKeyDialog(self)
                    if dialog.exec_() == QDialog.Accepted:
                        email = dialog.email_input.text()
                        name = dialog.name_input.text()
                        password = dialog.password_input.text()
                    key_ring = logic.PublicKeyRing(name, email, public_key)
                    self.add_public_key(key_ring)
                    return public_key
                except ValueError:
                    pass
                print("Error: The file does not contain a valid private or public key.")
                return None
        else:
            print("No file selected.")
            return None

    def export_private_key(self):
        selected_items = self.list_widget_1.selectedItems()
        if not selected_items:
            return
        for i in self.privateRings:
            if i.keyID == selected_items[0].data(Qt.UserRole):
                self.privateKey = i
                break

        file_name = self.privateKey.email + "_" + self.privateKey.name + "PR.pem"
        file_path = os.path.join("keys", file_name)
        with open(file_path, "wb") as file:
            file.write(self.privateKey.private_key)

        print("Private key exported successfully.")

    def export_public_key(self):
        selected_items = self.list_widget_1.selectedItems()
        if not selected_items:
            return
        for i in self.privateRings:
            if i.keyID == selected_items[0].data(Qt.UserRole):
                self.privateKey = i
                break

        file_name = self.privateKey.email + "_" + self.privateKey.name + "PU.pem"
        file_path = os.path.join("keys", file_name)
        with open(file_path, "wb") as file:
            file.write(self.privateKey.public_key)

        print("Public key exported successfully.")

    def details_private_key(self):
        selected_items = self.list_widget_1.selectedItems()
        if not selected_items:
            return
        for i in self.privateRings:
            if i.keyID == selected_items[0].data(Qt.UserRole):
                self.privateKey = i
                break


        dialog = QDialog(self)
        dialog.setWindowTitle("Details Private Key")
        dialog.setGeometry(700, 250, 430, 450)
        main_layout = QVBoxLayout(dialog)

        table = QTableWidget(6, 1, dialog)
        main_layout.addWidget(table)
        table.setHorizontalHeaderLabels(["Value"])
        headers = ["Email", "Name", "KeyID", "TimeStamp", "Private Key", "Public Key"]
        for row, header in enumerate(headers):
            table.setVerticalHeaderItem(row, QTableWidgetItem(header))

        table.setItem(0, 0, QTableWidgetItem(self.privateKey.email))
        table.setItem(1, 0, QTableWidgetItem(self.privateKey.name))
        table.setItem(2, 0, QTableWidgetItem(str(self.privateKey.keyID)))
        table.setItem(3, 0, QTableWidgetItem(self.privateKey.timestamp.strftime('%d.%m.%Y %H:%M:%S')))
        # Pretvaranje bajtnog niza u string (dekodiranje)
        public_key_str = self.privateKey.public_key.decode('utf-8')
        start_idx = public_key_str.find('-----BEGIN PUBLIC KEY-----\n') + len('-----BEGIN PUBLIC KEY-----\n')
        end_idx = public_key_str.find('\n-----END PUBLIC KEY-----\n')
        public_key_trimmed = public_key_str[start_idx:end_idx]
        private_key_str = self.privateKey.private_key.decode('utf-8')
        start_idx = private_key_str.find('-----BEGIN PRIVATE KEY-----\n') + len('-----BEGIN PRIVATE KEY-----\n')
        end_idx = private_key_str.find('\n-----END PRIVATE KEY-----\n')
        private_key_trimmed = private_key_str[start_idx:end_idx]

        text_edit = QTextEdit()
        text_edit.setPlainText(str(private_key_trimmed))
        text_edit.setReadOnly(True)
        text_edit.setWordWrapMode(QTextOption.WrapAnywhere)
        text_edit.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        text_edit.setMinimumWidth(300)
        table.setCellWidget(4, 0, text_edit)
        table.setRowHeight(4, 100)

        text_edit1 = QTextEdit()
        text_edit1.setPlainText(str(public_key_trimmed))
        text_edit1.setReadOnly(True)
        text_edit1.setWordWrapMode(QTextOption.WrapAnywhere)
        text_edit1.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        text_edit1.setMinimumWidth(300)
        table.setRowHeight(5, 100)
        table.setCellWidget(5,0,text_edit1)

        table.setColumnWidth(0, 300)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.setHorizontalScrollBar(QScrollBar())

        button_layout = QHBoxLayout()
        main_layout.addLayout(button_layout)
        close_button = QPushButton("Close", dialog)
        close_button.clicked.connect(dialog.close)
        button_layout.addStretch(1)
        button_layout.addWidget(close_button)
        button_layout.addStretch(1)
        dialog.exec_()

    def details_public_key(self):
        selected_items = self.list_widget_2.selectedItems()
        if not selected_items:
            return
        for i in self.publicRings:
            if i.keyID == selected_items[0].data(Qt.UserRole):
                self.privateKey = i
                break


        dialog = QDialog(self)
        dialog.setWindowTitle("Details Public Key")
        dialog.setGeometry(700, 250, 430, 360)
        main_layout = QVBoxLayout(dialog)

        table = QTableWidget(5, 1, dialog)
        main_layout.addWidget(table)
        table.setHorizontalHeaderLabels(["Value"])
        headers = ["Email", "Name", "KeyID", "TimeStamp", "Public Key"]
        for row, header in enumerate(headers):
            table.setVerticalHeaderItem(row, QTableWidgetItem(header))

        table.setItem(0, 0, QTableWidgetItem(self.privateKey.email))
        table.setItem(1, 0, QTableWidgetItem(self.privateKey.name))
        table.setItem(2, 0, QTableWidgetItem(str(self.privateKey.keyID)))
        table.setItem(3, 0, QTableWidgetItem(self.privateKey.timestamp.strftime('%d.%m.%Y %H:%M:%S')))
        # Pretvaranje bajtnog niza u string (dekodiranje)
        public_key_str = self.privateKey.public_key.decode('utf-8')
        start_idx = public_key_str.find('-----BEGIN PUBLIC KEY-----\n') + len('-----BEGIN PUBLIC KEY-----\n')
        end_idx = public_key_str.find('\n-----END PUBLIC KEY-----\n')
        public_key_trimmed = public_key_str[start_idx:end_idx]

        text_edit1 = QTextEdit()
        text_edit1.setPlainText(public_key_trimmed)
        text_edit1.setReadOnly(True)
        text_edit1.setWordWrapMode(QTextOption.WrapAnywhere)
        text_edit1.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        text_edit1.setMinimumWidth(300)
        table.setRowHeight(4, 100)
        table.setCellWidget(4,0,text_edit1)

        table.setColumnWidth(0, 300)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.setHorizontalScrollBar(QScrollBar())

        button_layout = QHBoxLayout()
        main_layout.addLayout(button_layout)
        close_button = QPushButton("Close", dialog)
        close_button.clicked.connect(dialog.close)
        button_layout.addStretch(1)
        button_layout.addWidget(close_button)
        button_layout.addStretch(1)
        dialog.exec_()

class NewKeyDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.mainWind = parent
        self.setWindowTitle("Input Window")
        self.setGeometry(750, 250, 300, 250)
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)
        form_layout = QFormLayout()
        main_layout.addLayout(form_layout)

        self.mail = QLineEdit()
        form_layout.addRow(QLabel("Mail:"), self.mail)
        self.name = QLineEdit()
        form_layout.addRow(QLabel("Name:"), self.name)
        self.password = QLineEdit()
        form_layout.addRow(QLabel("Password:"), self.password)

        radio_button1 = QRadioButton("1024")
        radio_button1.setChecked(True)
        self.radio_button2 = QRadioButton("2048")
        radio_button_layout = QHBoxLayout()
        radio_button_layout.addWidget(radio_button1)
        radio_button_layout.addWidget(self.radio_button2)
        form_layout.addRow(QLabel("Key size:"), radio_button_layout)

        # Kreiranje dugmeta ispod
        button_layout = QHBoxLayout()
        main_layout.addLayout(button_layout)
        generate_button = QPushButton("Submit")
        generate_button.clicked.connect(self.add_new_key)
        button_layout.addStretch(1)
        button_layout.addWidget(generate_button)
        button_layout.addStretch(1)

    def add_new_key(self):
        key = 1024
        if self.radio_button2.isChecked():
            key = 2048
        (private_key, public_key) = logic.generate_rsa_keys(key)
        keyRing = logic.PrivateKeyRing(self.name.text(), self.mail.text(), private_key)
        self.mainWind.add_private_key(keyRing)

class ImportKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Details")
        self.setGeometry(700, 300, 300, 200)

        layout = QVBoxLayout(self)
        form_layout = QFormLayout()
        layout.addLayout(form_layout)

        self.email_input = QLineEdit()
        form_layout.addRow("Email:", self.email_input)
        self.name_input = QLineEdit()
        form_layout.addRow("Name:", self.name_input)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Password:", self.password_input)

        accept_button = QPushButton("Accept")
        accept_button.clicked.connect(self.accept)
        layout.addWidget(accept_button)


class SendDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Send message")
        self.setGeometry(700, 250, 400, 500)

        self.tb_message = QTextEdit(self)
        self.tb_message.setFixedHeight(150)
        self.check_encrypt = QCheckBox("Encrypt", self)
        self.check_encrypt.stateChanged.connect(self.encript_toggle)
        self.check_sign = QCheckBox("Sign", self)
        self.check_sign.stateChanged.connect(self.sign_toggle)
        self.check_base64 = QCheckBox("Radix-64 encode", self)
        self.check_compress = QCheckBox("Compress", self)
        self.check_layout = QHBoxLayout()
        self.check_layout.addWidget(self.check_sign)
        self.check_layout.addWidget(self.check_encrypt)
        self.check_layout.addWidget(self.check_base64)
        self.check_layout.addWidget(self.check_compress)

        self.combo_signing_key = QComboBox(self)
        for pk in MainWindow.privateRings:
            self.combo_signing_key.addItem(pk.email + "->" + pk.name, userData=pk)
        self.combo_signing_key.setDisabled(1)
        self.combo_encryption_key = QComboBox(self)
        for pk in MainWindow.publicRings:
            self.combo_encryption_key.addItem(pk.email + "->" + pk.name, userData=pk)
        self.combo_encryption_key.setDisabled(1)
        self.combo_encryption_algorithm = QComboBox(self)
        self.combo_encryption_algorithm.addItem("AES-128", userData="AES")
        self.combo_encryption_algorithm.addItem("Triple DES", userData="3DES")
        self.combo_encryption_algorithm.setDisabled(1)

        self.tb_passphrase = QLineEdit(self)
        self.tb_passphrase.setDisabled(1)
        self.button_box = QHBoxLayout()
        self.button_ok = QPushButton("Send", self)
        self.button_cancel = QPushButton("Cancel", self)

        # Layouts
        self.main_layout = QVBoxLayout(self)
        self.main_layout.addWidget(QLabel("Message:", self))
        self.main_layout.addWidget(self.tb_message)
        self.main_layout.addSpacing(30)
        self.main_layout.addLayout(self.check_layout)
        self.main_layout.addSpacing(30)
        self.main_layout.addWidget(QLabel("Signing key:", self))
        self.main_layout.addWidget(self.combo_signing_key)
        self.x = QHBoxLayout(self)
        self.x.addWidget(QLabel("Signing passphrase:", self))
        self.x.addWidget(self.tb_passphrase)
        self.main_layout.addLayout(self.x)
        self.main_layout.addWidget(QLabel("Encryption key:", self))
        self.main_layout.addWidget(self.combo_encryption_key)
        self.main_layout.addWidget(QLabel("Encryption algorithm:", self))
        self.main_layout.addWidget(self.combo_encryption_algorithm)
        self.main_layout.addSpacing(70)
        self.main_layout.addStretch(1)

        self.main_layout.addLayout(self.button_box)
        self.button_box.addWidget(self.button_ok)
        self.button_box.addWidget(self.button_cancel)
        self.button_ok.clicked.connect(self.send_message)
        self.button_cancel.clicked.connect(self.reject)


    def send_message(self):
        self.sign = self.check_sign.isChecked()
        self.encript = self.check_encrypt.isChecked()
        self.compress = self.check_compress.isChecked()
        self.translate = self.check_base64.isChecked()

        self.privateKey = self.combo_signing_key.currentData() if self.sign else None
        self.publicKey = self.combo_encryption_key.currentData() if self.encript else None
        self.algorithm = self.combo_encryption_algorithm.currentData() if self.encript else None
        self.message = self.tb_message.toPlainText()

        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "Text Files (*.txt)", options=options)

        logic.sendMessage(self.message,self.privateKey,self.publicKey,self.algorithm,self.compress,self.translate,self.sign,self.encript,file_path)

    def encript_toggle(self):
        if self.check_encrypt.isChecked():
            self.combo_encryption_key.setEnabled(1)
            self.combo_encryption_algorithm.setEnabled(1)
        else:
            self.combo_encryption_key.setDisabled(1)
            self.combo_encryption_algorithm.setDisabled(1)

    def sign_toggle(self):
        if self.check_sign.isChecked():
            self.combo_signing_key.setEnabled(1)
            self.tb_passphrase.setEnabled(1)
        else:
            self.combo_signing_key.setDisabled(1)
            self.tb_passphrase.setDisabled(1)

class ReceiveDialog(QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Send message")
        self.setGeometry(700, 250, 400, 400)
        self.main_layout = QVBoxLayout(self)

        file_dialog = QFileDialog()

        if file_dialog.exec_() == QFileDialog.Accepted:
            file_path = file_dialog.selectedFiles()[0]
        else:
            return
        (self.fields, self.privateKey, self.publicKey) = logic.receiveMessage(MainWindow.privateRings, MainWindow.publicRings, file_path)

        table = QTableWidget(6, 1, self)
        self.main_layout.addWidget(table)
        table.setHorizontalHeaderLabels(["Value"])
        headers = ["Message", "Compress", "Radix64", "Signing Key", "Verified", "Encription Key"]
        for row, header in enumerate(headers):
            table.setVerticalHeaderItem(row, QTableWidgetItem(header))

        table.setItem(1, 0, QTableWidgetItem(self.fields["Compressed"]))
        table.setItem(2, 0, QTableWidgetItem(self.fields["Radix-64"]))
        table.setItem(3, 0, QTableWidgetItem(self.privateKey.email))
        table.setItem(4, 0, QTableWidgetItem("False"))
        table.setItem(5, 0, QTableWidgetItem(self.publicKey.email))

        text_edit1 = QTextEdit()
        text_edit1.setPlainText("message")
        text_edit1.setReadOnly(True)
        text_edit1.setWordWrapMode(QTextOption.WrapAnywhere)
        text_edit1.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        text_edit1.setMinimumWidth(300)
        table.setRowHeight(0, 100)
        table.setCellWidget(0, 0, text_edit1)

        table.setColumnWidth(0, 300)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.setHorizontalScrollBar(QScrollBar())

        button_layout = QHBoxLayout()
        self.main_layout.addLayout(button_layout)
        close_button = QPushButton("Close", self)
        close_button.clicked.connect(self.close)
        button_layout.addStretch(1)
        button_layout.addWidget(close_button)
        button_layout.addStretch(1)








if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
