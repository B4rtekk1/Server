import 'package:flutter/material.dart';

class Filesicons {
  static const Map<String, String> exToIcon = {
    "pdf": "assets/icons/pdf.png",
    //"doc": "assets/icons/doc.png",
    "docx": "assets/icons/doc.png",
    "odt": "assets/icons/odt.png",
    "ai": "assets/icons/ai.png",
    "psd": "assets/icons/psd.png",
    "bmp": "assets/icons/bmp.png",
    "md": "assets/icons/md.png",
    "tex": "assets/icons/tex.png",
    "tif": "assets/icons/tif.png",
    "folder": "assets/icons/folder.png",
    //"xls": "assets/icons/xls.png",
    //"xlsx": "assets/icons/xls.png",
    //"ppt": "assets/icons/ppt.png",
    //"pptx": "assets/icons/ppt.png",
    "txt": "assets/icons/txt.png",
    "jpg": "assets/icons/jpg.png",
    "jpeg": "assets/icons/jpg.png",
    "png": "assets/icons/png.png",
    "gif": "assets/icons/gif.png",
    //"zip": "assets/icons/zip.png",
    //"rar": "assets/icons/zip.png",
    //"7z": "assets/icons/zip.png",
    //"tar": "assets/icons/zip.png",
    //"gz": "assets/icons/zip.png",
    //"mp3": "assets/icons/mp3.png",
    //"wav": "assets/icons/mp3.png",
    //"flac": "assets/icons/mp3.png",
    //"mp4": "assets/icons/mp4.png",
    //"avi": "assets/icons/mp4.png",
    //"mkv": "assets/icons/mp4.png",
    //"mov": "assets/icons/mp4.png",
    //"wmv": "assets/icons/mp4.png",
    //"webm": "assets/icons/mp4.png",
    //"flv": "assets/icons/mp4.png",
    //"ogg": "assets/icons/mp4.png",
    //"webp": "assets/icons/webp.png",
    "svg": "assets/icons/svg.png",
    //"html": "assets/icons/html.png",
    //"css": "assets/icons/css.png",
    //"js": "assets/icons/js.png",
    //"json": "assets/icons/json.png",
    //"xml": "assets/icons/xml.png",
    //"apk": "assets/icons/apk.png",
    //"exe": "assets/icons/exe.png",
    //"iso": "assets/icons/iso.png",
    //"torrent": "assets/icons/torrent.png",
    "default": "assets/icons/file.png",
  };

  static Widget getIconForExtension(String extension) {
    final iconPath = exToIcon[extension.toLowerCase()] ?? 'assets/icons/file.png';
    return Image.asset(
      iconPath,
      width: 24,
      height: 24,
      fit: BoxFit.contain,
    );
  }
}