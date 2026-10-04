"""Native priority editor with explicit ignored criteria."""
from .recommendation_policy import RecommendationPolicy, LABELS, DEFAULT_ORDER


def edit_policy(parent, policy):
    import tkinter as tk
    from tkinter import ttk
    from .ui_theme import apply_review_theme, checkbox_images
    dialog = tk.Toplevel(parent)
    apply_review_theme(dialog)
    dialog.title("추천 기준 설정")
    dialog.geometry("640x660")
    dialog.transient(parent)
    body = ttk.Frame(dialog, padding=16)
    body.pack(fill="both", expand=True)
    mode = tk.StringVar(value=policy.mode)
    ttk.Radiobutton(body, text="사용자 우선순위 · 위 항목이 동급일 때만 다음 항목 비교", variable=mode, value="priority").pack(anchor="w")
    ttk.Radiobutton(body, text="기존 엄격 비교 · 항목 간 우위가 갈리면 검토 필요", variable=mode, value="strict").pack(anchor="w", pady=(6, 12))
    ttk.Label(body, text="체크를 끄면 추천에서 제외합니다. 항목을 고르고 위/아래로 옮기세요.").pack(anchor="w")
    tree = ttk.Treeview(body, columns=("rule",), show="tree headings", height=8, selectmode="browse")
    tree.heading("#0", text="사용 · 우선순위")
    tree.heading("rule", text="선호 기준")
    tree.column("#0", width=230)
    tree.column("rule", width=340)
    tree.pack(fill="both", expand=True, pady=8)
    checks = checkbox_images(dialog)
    enabled = set(policy.order)
    order = list(policy.order) + [key for key in DEFAULT_ORDER if key not in enabled]
    rules = {"language": "한국어 > 일본어 > 영어 > 중국어 > 기타", "pages": "많은 쪽", "resolution": "높은 쪽",
             "size": "큰 쪽", "mosaic": "무수정 > 디센서 > 유모 (제목 표기)", "color": "풀컬러 > 흑백",
             "title": "[서클(작가)] 제목 > [이름] 제목 > 일반 제목", "mtime": "최근 수정된 쪽"}
    def render(selected=None):
        tree.delete(*tree.get_children())
        for index, key in enumerate(order):
            tree.insert("", "end", iid=key, text=f"  {index+1}. {LABELS[key]}",
                        image=checks[int(key in enabled)], values=(rules[key],))
        if selected:
            tree.selection_set(selected)
    def toggle(event=None):
        key = tree.identify_row(event.y) if event is not None else next(iter(tree.selection()), None)
        if key:
            enabled.discard(key) if key in enabled else enabled.add(key)
            render(key)
    def click(event):
        if event.x < 45:
            toggle(event)
            return "break"
    tree.bind("<Button-1>", click)
    tree.bind("<space>", lambda event: toggle())
    tree.bind("<Double-Button-1>", toggle)
    def move(delta):
        if tree.selection():
            key = tree.selection()[0]
            index = order.index(key)
            target = max(0, min(len(order)-1, index+delta))
            order[index], order[target] = order[target], order[index]
            render(key)
    controls = ttk.Frame(body); controls.pack(fill="x")
    ttk.Button(controls, text="위로", command=lambda: move(-1)).pack(side="left")
    ttk.Button(controls, text="아래로", command=lambda: move(1)).pack(side="left", padx=6)
    ttk.Button(controls, text="고려 / 제외", command=toggle).pack(side="left")
    ttk.Label(body, text="언어 미상·추정은 해당 우선순위에 도달하면 검토 필요로 남습니다.\n모자이크·컬러 미상은 건너뜁니다. 전체 동급이면 임의로 추천하지 않습니다.\n저장하면 모든 그룹의 추천을 갱신합니다. 직접 검토한 결과는 그대로 유지됩니다.", wraplength=600).pack(fill="x", pady=16)
    result = None
    def save():
        nonlocal result
        result = RecommendationPolicy(mode.get(), tuple(key for key in order if key in enabled))
        dialog.destroy()
    footer = ttk.Frame(body); footer.pack(fill="x")
    ttk.Button(footer, text="저장하고 추천 갱신", command=save, style="Primary.TButton").pack(side="left")
    ttk.Button(footer, text="취소", command=dialog.destroy).pack(side="right")
    render()
    from .dialogs import center_dialog
    center_dialog(dialog, parent)
    dialog.grab_set()
    dialog.wait_window()
    return result
