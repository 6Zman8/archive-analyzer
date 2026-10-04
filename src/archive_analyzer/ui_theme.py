"""Compact dark styling shared by the native review controls."""
def apply_review_theme(window):
    from tkinter import ttk
    from tkinter import font
    style = ttk.Style(window)
    style.theme_use("clam")
    # Explicit CJK outline font prevents Tk's Segoe fallback to bitmap glyphs.
    family = "Malgun Gothic"
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkTooltipFont"):
        font.nametofont(name, root=window).configure(family=family, size=10)
    window.option_add("*Font", (family, 10))
    bg, panel, ink, border = "#191d24", "#20252d", "#e7edf5", "#3a4350"
    style.configure(".", background=bg, foreground=ink, bordercolor=border,
                    lightcolor=border, darkcolor=border, font=(family, 10))
    style.configure("TButton", padding=(9, 5), background="#2a313c")
    style.map("TButton", background=[("active", "#354254"), ("disabled", "#232831")],
              foreground=[("disabled", "#8d97a6")])
    style.configure("TMenubutton", padding=(9, 5), background="#2a313c", arrowsize=8, arrowcolor=ink)
    style.map("TMenubutton", background=[("active", "#354254"), ("disabled", "#232831")],
              foreground=[("disabled", "#8d97a6")])
    for name, color, active in (("Primary", "#285b91", "#3978b7"),
                                ("Keep", "#205b48", "#2c7960"),
                                ("Caution", "#73512b", "#946a36"),
                                ("Danger", "#713840", "#92454f")):
        style.configure(f"{name}.TButton", background=color, foreground="#ffffff")
        style.map(f"{name}.TButton", background=[("disabled", "#232831"), ("active", active)],
                  foreground=[("disabled", "#8d97a6")])
    style.configure("TCheckbutton", indicatorbackground=panel, indicatormargin=4)
    style.map("TCheckbutton", indicatorbackground=[("selected", "#79aff1"), ("!selected", "#384454")])
    style.configure("TEntry", fieldbackground=panel, insertcolor=ink)
    style.configure("TCombobox", fieldbackground=panel, arrowcolor=ink)
    style.map("TCombobox", fieldbackground=[("readonly", panel)], foreground=[("readonly", ink)])
    style.configure("Treeview", background=panel, fieldbackground=panel,
                    foreground=ink, rowheight=24, borderwidth=0)
    style.map("Treeview", background=[("selected", "#284e79")], foreground=[])
    style.configure("Members.Treeview", rowheight=44)
    style.configure("Treeview.Heading", background="#2a313c", foreground="#c8d4e5", padding=(5, 5))
    style.map("Treeview.Heading", background=[("active", "#354254")])
    style.configure("TNotebook", background=bg, borderwidth=0)
    style.configure("TNotebook.Tab", background="#252b34", padding=(7, 5))
    style.map("TNotebook.Tab", background=[("selected", "#284e79")], foreground=[("selected", "#ffffff")])
    style.configure("TProgressbar", background="#79aff1", troughcolor=panel)
    style.configure("TScrollbar", background="#465264", troughcolor=bg, arrowcolor=ink)
    for orient in ("Horizontal", "Vertical"):
        name = f"{orient}.TScrollbar"
        style.configure(name, background="#465264", troughcolor=bg, bordercolor=bg,
                        lightcolor=bg, darkcolor=bg, arrowcolor=ink)
        style.map(name, background=[("disabled", bg), ("active", "#687b96")],
                  arrowcolor=[("disabled", bg)])
    window.configure(background=bg)
    window.option_add("*Listbox.background", panel)
    window.option_add("*Listbox.foreground", ink)
    window.option_add("*Listbox.selectBackground", "#284e79")
    window.option_add("*Menu.background", panel)
    window.option_add("*Menu.foreground", ink)
    window.option_add("*Menu.activeBackground", "#284e79")
    window.option_add("*Menu.activeForeground", "#ffffff")


def action_style(text):
    if "휴지통" in text:
        return "Danger.TButton"
    if text == "보존" or "되돌리기" in text:
        return "Keep.TButton"
    if "제거 후보" in text or "격리" in text and "폴더" not in text or "추정값" in text:
        return "Caution.TButton"
    if "정밀분석" in text or "추천값" in text:
        return "Primary.TButton"
    return "TButton"


def checkbox_images(master):
    """Draw checks as pixels, independent of the installed symbol fonts."""
    from PIL import Image, ImageDraw, ImageTk
    result = []
    for selected in (False, True):
        image = Image.new("RGB", (22, 22), "#20252d")
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((2, 2, 19, 19), radius=3,
                               fill="#79aff1" if selected else "#29323e",
                               outline="#a4bad4", width=2)
        if selected:
            draw.line(((6, 10), (9, 14), (16, 7)), fill="#122337", width=3)
        result.append(ImageTk.PhotoImage(image, master=master))
    return tuple(result)
