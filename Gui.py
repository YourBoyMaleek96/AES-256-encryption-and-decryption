import customtkinter as ctk
from Week12program import encrypt, decrypt

class AESGui:
    def __init__(self):
        # Configure appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Create main window
        self.window = ctk.CTk()
        self.window.title("AES-256 Encryption/Decryption")
        self.window.geometry("800x600")

        # Create main frame
        self.frame = ctk.CTkFrame(self.window)
        self.frame.pack(pady=20, padx=20, fill="both", expand=True)

        # Title
        self.title = ctk.CTkLabel(self.frame, text="AES-256 Encryption/Decryption", font=("Arial", 24, "bold"))
        self.title.pack(pady=20)

        # Input fields
        self.text_label = ctk.CTkLabel(self.frame, text="Enter Text (32 hex characters):")
        self.text_label.pack(pady=5)
        self.text_entry = ctk.CTkEntry(self.frame, width=600)
        self.text_entry.pack(pady=5)
        self.text_hint = ctk.CTkLabel(self.frame, text="Hint: 00112233445566778899aabbccddeeff", text_color="gray")
        self.text_hint.pack()

        self.key_label = ctk.CTkLabel(self.frame, text="Enter Key (64 hex characters):")
        self.key_label.pack(pady=5)
        self.key_entry = ctk.CTkEntry(self.frame, width=600)
        self.key_entry.pack(pady=5)
        self.key_hint = ctk.CTkLabel(self.frame, text="Hint: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", text_color="gray")
        self.key_hint.pack()

        # Buttons frame
        self.button_frame = ctk.CTkFrame(self.frame)
        self.button_frame.pack(pady=20)

        self.encrypt_button = ctk.CTkButton(self.button_frame, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(side="left", padx=10)

        self.decrypt_button = ctk.CTkButton(self.button_frame, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(side="left", padx=10)

        # Result
        self.result_label = ctk.CTkLabel(self.frame, text="Result:")
        self.result_label.pack(pady=5)
        self.result_text = ctk.CTkTextbox(self.frame, width=600, height=200)
        self.result_text.pack(pady=5)

    def validate_input(self, text, key):
        """Validate hex input and length"""
        try:
            text_bytes = bytes.fromhex(text)
            key_bytes = bytes.fromhex(key)

            if len(text_bytes) != 16:
                raise ValueError("Text must be exactly 16 bytes (32 hex characters)")
            if len(key_bytes) != 32:
                raise ValueError("Key must be exactly 32 bytes (64 hex characters)")

            return text_bytes, key_bytes

        except ValueError as e:
            self.result_text.delete("1.0", "end")
            self.result_text.insert("1.0", f"Error: {str(e)}")
            return None

    def encrypt(self):
        """Handle encryption"""
        text = self.text_entry.get().strip()
        key = self.key_entry.get().strip()

        validated = self.validate_input(text, key)
        if validated:
            text_bytes, key_bytes = validated
            try:
                result = encrypt(text_bytes, key_bytes)
                self.result_text.delete("1.0", "end")
                self.result_text.insert("1.0", f"Encrypted (hex): {result.hex()}")
            except Exception as e:
                self.result_text.delete("1.0", "end")
                self.result_text.insert("1.0", f"Error: {str(e)}")

    def decrypt(self):
        """Handle decryption"""
        text = self.text_entry.get().strip()
        key = self.key_entry.get().strip()

        validated = self.validate_input(text, key)
        if validated:
            text_bytes, key_bytes = validated
            try:
                result = decrypt(text_bytes, key_bytes)
                self.result_text.delete("1.0", "end")
                self.result_text.insert("1.0", f"Decrypted (hex): {result.hex()}")
            except Exception as e:
                self.result_text.delete("1.0", "end")
                self.result_text.insert("1.0", f"Error: {str(e)}")

    def run(self):
        """Start the GUI"""
        self.window.mainloop()

if __name__ == "__main__":
    app = AESGui()
    app.run()
