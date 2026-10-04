"""Keep a menu command and its optional toolbar button in the same state."""
from __future__ import annotations


class MenuAction:
    def __init__(self, menu, label, callback):
        self.menu, self.callback = menu, callback
        self.widgets = []
        menu.add_command(label=label, command=self.invoke)
        self.index = menu.index("end")

    def configure(self, *, state):
        self.menu.entryconfigure(self.index, state=state)
        for widget in self.widgets:
            widget.configure(state=state)

    def cget(self, option):
        return self.menu.entrycget(self.index, "label" if option == "text" else option)

    def invoke(self):
        if self.cget("state") != "disabled":
            return self.callback()

    def add_button(self, parent, *, text=None, style="TButton"):
        from tkinter import ttk
        button = ttk.Button(parent, text=text or self.cget("text"), command=self.invoke,
                            state=self.cget("state"), style=style)
        self.widgets.append(button)
        return button
