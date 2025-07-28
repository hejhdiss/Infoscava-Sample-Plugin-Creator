import sys
import base64
import json
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox,
    QComboBox
)
TEMPLATES = {
    "YARA": "scan_yara",
    "ExifTool": "extract_exif",
    "Strings": "extract_strings",
    "Sigcheck": "check_signature"
}
RETURN_TEMPLATES = {
    "JSON": '''        return {
            "Scan Output": result.stdout.strip(),
            "Errors": result.stderr.strip()
        }''',

    "HTML": '''        html_content = f"<h3>Scan Output</h3><pre>{result.stdout}</pre>"
        return {
            "infoscava_output_type": "html",
            "content": html_content
        }''',

    "Plain Text": '''        return result.stdout.strip()'''
}
class PluginCreator(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Infoscava Plugin Creator")
        layout = QVBoxLayout()
        self.name_input = self._add_field(layout, "Plugin Name:")
        self.desc_input = self._add_field(layout, "Description:")
        self.tab_input = self._add_field(layout, "Tab Title:")
        layout.addWidget(QLabel("Tool Type:"))
        self.tool_selector = QComboBox()
        self.tool_selector.addItems(TEMPLATES.keys())
        layout.addWidget(self.tool_selector)
        exe_row = QHBoxLayout()
        self.exe_input = QLineEdit()
        exe_browse = QPushButton("Browse")
        exe_browse.clicked.connect(self.browse_exe)
        exe_row.addWidget(QLabel("Executable:"))
        exe_row.addWidget(self.exe_input)
        exe_row.addWidget(exe_browse)
        layout.addLayout(exe_row)
        self.args_input = self._add_field(layout, "Optional CLI Args:")
        layout.addWidget(QLabel("Return Format:"))
        self.return_style = QComboBox()
        self.return_style.addItems(["JSON", "HTML", "Plain Text"])
        layout.addWidget(self.return_style)
        create_btn = QPushButton("Create Plugin")
        create_btn.clicked.connect(self.create_plugin)
        layout.addWidget(create_btn)
        self.setLayout(layout)
    def _add_field(self, layout, label):
        layout.addWidget(QLabel(label))
        field = QLineEdit()
        layout.addWidget(field)
        return field
    def browse_exe(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Executable", "", "Executables (*.exe)")
        if path:
            self.exe_input.setText(path)
    def create_plugin(self):
        name = self.name_input.text().strip()
        desc = self.desc_input.text().strip()
        tab = self.tab_input.text().strip() or name
        tool = self.tool_selector.currentText()
        exe = self.exe_input.text().strip()
        args = self.args_input.text().strip()
        ret_type = self.return_style.currentText()
        if not name or not desc or not tool or not exe:
            QMessageBox.warning(self, "Missing Fields", "Please fill in all required fields.")
            return
        fn_name = TEMPLATES[tool]
        return_block = RETURN_TEMPLATES[ret_type]
        args_part = ""
        if args:
            safe_args = '", "'.join(args.split())
            args_part = f', "{safe_args}"'
        safe_exe_path = exe.replace("\\", "\\\\")
        code = (
            f'def {fn_name}(filepath, file_content):\n'
            f'    import subprocess\n'
            f'    try:\n'
            f'        result = subprocess.run(\n'
            f'            ["{safe_exe_path}"{args_part}, filepath],\n'
            f'            capture_output=True, text=True\n'
            f'        )\n'
            f'{return_block}\n'
            f'    except Exception as e:\n'
            f'        return {{"error": str(e)}}\n'
        )
        b64_code = base64.b64encode(code.encode("utf-8")).decode("utf-8")

        plugin = {
            "name": name,
            "function_name": fn_name,
            "type": "analysis_plugin",
            "description": desc,
            "tab_title": tab,
            "python_code": b64_code
        }
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Plugin", f"{name}.infoscava", "Infoscava Plugins (*.infoscava)")
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(plugin, f, indent=4)
            QMessageBox.information(self, "Done", f"✅ Plugin saved to:\n{save_path}")
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = PluginCreator()
    win.resize(520, 400)
    win.show()
    sys.exit(app.exec())
