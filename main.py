import sys
import base64
import json
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox,
    QComboBox
)
CLEANING_FUNCTIONS_CODE = """
def clean_sigcheck(raw_text, output_format='text'):
    lines = raw_text.strip().splitlines()
    cleaned_lines = []
    table = {}

    # Skip first 3 lines (version + copyright)
    lines = lines[3:]

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.endswith(":"):
            filename = line.rstrip(":")
            table["File"] = filename
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            table[key.strip()] = value.strip()

    if output_format == 'json':
        return table

    elif output_format == 'html':
        html = '<table border="1" cellpadding="5" cellspacing="0">\\n'
        html += '<thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>\\n'
        for key, value in table.items():
            html += f'<tr><td>{key}</td><td>{value}</td></tr>\\n'
        html += '</tbody></table>'
        # Modified to return in the expected dictionary format for HTML output
        return {"infoscava_output_type": "html", "content": html}

    else:  # Plain text
        return '\\n'.join(f"{k}: {v}" for k, v in table.items())

def clean_yara_output(raw_output: str, return_type: str = "Plain Text"):
    lines = raw_output.strip().splitlines()
    parsed = []

    for line in lines:
        parts = line.split()
        if len(parts) >= 4:
            parsed.append({
                "rule": parts[0],
                "file": parts[1],
                "offset": parts[2],
                "match": " ".join(parts[3:])
            })

    if return_type == "Plain Text":
        return "\\n".join([" ".join([d["rule"], d["file"], d["offset"], d["match"]]) for d in parsed])

    elif return_type == "HTML":
        content = "\\n".join([" ".join([d["rule"], d["file"], d["offset"], d["match"]]) for d in parsed])
        return {
            "infoscava_output_type": "html",
            "content": f"<pre>{content}</pre>"
        }

    elif return_type == "JSON":
        return parsed

    else:
        return {"error": "Invalid return type"}

def clean_exif_output(raw_output: str, return_type: str = "Plain Text"):
    lines = raw_output.splitlines()
    data = {}

    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            data[key.strip()] = value.strip()

    if return_type == "Plain Text":
        return "\\n".join(f"{k}: {v}" for k, v in data.items())

    elif return_type == "HTML":
        html_content = "<pre>" + "\\n".join(f"{k}: {v}" for k, v in data.items()) + "</pre>"
        return {
            "infoscava_output_type": "html",
            "content": html_content
        }

    elif return_type == "JSON":
        return data

    else:
        return {"error": "Invalid return type"}

def clean_strings_output(raw_output: str, return_type: str = "Plain Text"):
    lines = raw_output.splitlines()
    cleaned_lines = []
    max_banner_lines = 4
    skip_prefixes = ('Strings v', 'Copyright', 'Sysinternals')

    # Remove banner only from first 4 lines
    for i, line in enumerate(lines):
        if i < max_banner_lines and any(line.startswith(p) for p in skip_prefixes):
            continue
        cleaned_lines.extend(lines[i:])
        break

    cleaned_lines = [l.strip() for l in cleaned_lines if l.strip()]

    # Return format logic
    if return_type == "Plain Text":
        return "\\n".join(cleaned_lines)

    elif return_type == "HTML":
        html_lines = "".join(f"<li>{line}</li>" for line in cleaned_lines)
        html_output = f"<ol>{html_lines}</ol>"
        return {
            "infoscava_output_type": "html",
            "content": html_output
        }

    elif return_type == "JSON":
        return {str(i + 1): line for i, line in enumerate(cleaned_lines)}

    else:
        return {"error": "Invalid return type"}
"""
TEMPLATES = {
    "YARA": "scan_yara",
    "ExifTool": "extract_exif",
    "Strings": "extract_strings",
    "Sigcheck": "check_signature"
}
CLEANING_FUNCTION_MAP = {
    "YARA": "clean_yara_output",
    "ExifTool": "clean_exif_output",
    "Strings": "clean_strings_output",
    "Sigcheck": "clean_sigcheck"
}
class PluginCreator(QWidget):
    """
    A PySide6 application to create Infoscava analysis plugins.
    It allows users to define a plugin's name, description, associated
    executable, optional CLI arguments, and the desired output format.
    The generated plugin file will include built-in functions to clean
    and format the output from various security tools.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Infoscava Plugin Creator")
        self.init_ui()
    def init_ui(self):
        """Initializes the user interface elements."""
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
        self.resize(520, 400) 
    def _add_field(self, layout: QVBoxLayout, label: str) -> QLineEdit:
        """Helper to add a label and QLineEdit pair to a layout."""
        layout.addWidget(QLabel(label))
        field = QLineEdit()
        layout.addWidget(field)
        return field
    def browse_exe(self):
        """Opens a file dialog for the user to select an executable."""
        path, _ = QFileDialog.getOpenFileName(self, "Select Executable", "", "Executables (*.exe)")
        if path:
            self.exe_input.setText(path)
    def create_plugin(self):
        """
        Gathers user inputs, generates the Python code for the plugin,
        encodes it in Base64, and saves it as an .infoscava file.
        """
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
        cleaning_fn_name = CLEANING_FUNCTION_MAP[tool]
        return_statement = ""
        if tool == "Sigcheck":
            if ret_type == "Plain Text":
                return_statement = f'return {cleaning_fn_name}(result.stdout.strip(), output_format="text")'
            elif ret_type == "HTML":
                return_statement = f'return {cleaning_fn_name}(result.stdout.strip(), output_format="html")'
            elif ret_type == "JSON":
                return_statement = f'return {cleaning_fn_name}(result.stdout.strip(), output_format="json")'
        else:
            return_statement = f'return {cleaning_fn_name}(result.stdout.strip(), return_type="{ret_type}")'
        args_part = ""
        if args:
            safe_args = '", "'.join(args.split())
            args_part = f', "{safe_args}"'
        safe_exe_path = exe.replace("\\", "\\\\")
        code = (
            CLEANING_FUNCTIONS_CODE + 
            f'\n\ndef {fn_name}(filepath, file_content):\n' 
            f'    """\n'
            f'    Analyzes a file using {tool}.\n'
            f'    Args:\n'
            f'        filepath (str): The path to the file to analyze.\n'
            f'        file_content (bytes): The content of the file (not used by this plugin).\n'
            f'    Returns:\n'
            f'        dict or str: The cleaned output in the specified format, or an error dictionary.\n'
            f'    """\n'
            f'    import subprocess\n'
            f'    try:\n'
            f'        # Execute the external tool with the file path and arguments\n'
            f'        result = subprocess.run(\n'
            f'            ["{safe_exe_path}"{args_part}, filepath],\n'
            f'            capture_output=True, text=True, check=True # check=True raises CalledProcessError for non-zero exit codes\n'
            f'        )\n'
            f'        # Call the appropriate cleaning function based on tool type and desired return format\n'
            f'        {return_statement}\n'
            f'    except subprocess.CalledProcessError as e:\n'
            f'        return {{"error": f"Tool execution failed: {{e.stderr.strip()}}", "raw_output": e.stdout.strip()}}\n'
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
    win.show()
    sys.exit(app.exec())
