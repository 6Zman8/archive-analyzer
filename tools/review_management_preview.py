"""Render a disposable, invisible native review window for layout inspection."""
from pathlib import Path
from tempfile import TemporaryDirectory
from dataclasses import replace
import ctypes as c
import tkinter as tk
from unittest.mock import patch
from PIL import Image
from archive_analyzer import review_ui
from archive_analyzer.review_table import UiSettingsStore
from archive_analyzer.review_viewmodel import build_group_view
from tests.unit.test_precision_service import _repository_with_images

class Idle:
    def __init__(self,*args): pass
    def start(self): pass
    def submit_load(self): pass
    def poll_result(self): return None

def capture(window,path):
    user,gdi=c.windll.user32,c.windll.gdi32
    user.GetDC.restype=c.c_void_p
    gdi.CreateCompatibleDC.argtypes=[c.c_void_p];gdi.CreateCompatibleDC.restype=c.c_void_p
    gdi.CreateCompatibleBitmap.argtypes=[c.c_void_p,c.c_int,c.c_int];gdi.CreateCompatibleBitmap.restype=c.c_void_p
    gdi.SelectObject.argtypes=[c.c_void_p,c.c_void_p];gdi.SelectObject.restype=c.c_void_p
    user.PrintWindow.argtypes=[c.c_void_p,c.c_void_p,c.c_uint]
    gdi.GetDIBits.argtypes=[c.c_void_p,c.c_void_p,c.c_uint,c.c_uint,c.c_void_p,c.c_void_p,c.c_uint]
    gdi.DeleteObject.argtypes=[c.c_void_p];gdi.DeleteDC.argtypes=[c.c_void_p]
    user.ReleaseDC.argtypes=[c.c_void_p,c.c_void_p]
    hwnd=window.winfo_id();width,height=window.winfo_width(),window.winfo_height()
    dc=user.GetDC(hwnd);mem=gdi.CreateCompatibleDC(dc);bitmap=gdi.CreateCompatibleBitmap(dc,width,height);old=gdi.SelectObject(mem,bitmap)
    class Header(c.Structure):
        _fields_=[('size',c.c_uint32),('width',c.c_int32),('height',c.c_int32),('planes',c.c_uint16),('bits',c.c_uint16),('compression',c.c_uint32),('sizeimage',c.c_uint32),('x',c.c_int32),('y',c.c_int32),('used',c.c_uint32),('important',c.c_uint32)]
    try:
        assert user.PrintWindow(hwnd,mem,2)
        header=Header(40,width,-height,1,32,0,0,0,0,0,0);pixels=c.create_string_buffer(width*height*4)
        gdi.SelectObject(mem,old)
        assert gdi.GetDIBits(mem,bitmap,0,height,pixels,c.byref(header),0)
        Image.frombuffer('RGB',(width,height),pixels,'raw','BGRX',0,1).save(path)
    finally:
        gdi.DeleteObject(bitmap);gdi.DeleteDC(mem);user.ReleaseDC(hwnd,dc)

with TemporaryDirectory() as directory:
    base=Path(directory);repo,_,_= _repository_with_images(base,(6,6));group=build_group_view(repo.review_group_details('precision-set'));repo.close()
    members=tuple(replace(group.members[i%2],archive_id=i+1,member_number=i+1,file_name=f'[해오름(윤)] 여름 산책 日本語 中文 [{i+1}판].zip', recommendation_text='보존 추천' if i==0 else '제거 후보 추천',language_text='한국어 (파일명 추정)' if i%2==0 else '일본어 (정밀분석)') for i in range(4))
    group=replace(group,members=members)
    root=tk.Tk();root.withdraw()
    with patch.object(review_ui,'ReviewWorker',Idle),patch.object(review_ui,'ThumbnailWorker',Idle),patch.object(review_ui.ReviewWindow,'_request_previews',lambda *a,**k:None),patch.object(review_ui,'UiSettingsStore',lambda:UiSettingsStore(base/'ui.json')):
        try:
            window=review_ui.ReviewWindow(root,base/'index.db',base);window._window.attributes('-alpha',0);window._window.attributes('-toolwindow',True)
            window._render_groups(tuple(replace(group,group_key=f'g{i}',set_key=f'g{i}',work_label=f'[해오름(윤)] 日本語 여름 산책 {i:03}', recommendation_text="보존 추천: 1번 파일", recommendation_status="RECOMMENDED") for i in range(600)))
            window._finish_operation()
            window._status.set("완료 · 이미지 정밀분석 · 600개 그룹")
            window._operation_progress.configure(value=1)
            for width,height in ((1440,960),(1280,860)):
                window._window.geometry(f'{width}x{height}');root.update();root.update_idletasks()
                for index,(image,name,page) in enumerate(window._preview_slots):
                    image.configure(text='비교 이미지 영역');name.configure(text=f'{"A" if index==0 else "B"} · {index+1}번 · {members[index].file_name}\nE:\\보관함\\예시');page.configure(text='12 / 32 페이지')
                root.update();capture(window._window,Path(f'build/ux-followup-preview-{width}.png'))
                print(width,'group-height',window._group_tree.winfo_height(),'member-height',window._member_tree.winfo_height(),'preview-height',window._preview_slots[0][0].winfo_height())
        finally:
            root.destroy()
