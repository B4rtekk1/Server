class FileItem {
  final String path;
  final String type;
  final String modified;

  FileItem({
    required this.path,
    required this.type,
    required this.modified,
  });

  factory FileItem.fromJSON(Map<String, dynamic> json) {
    return FileItem(
      path: json["path"] as String,
      type: json["type"] as String,
      modified: json["modified"] as String,
    );
  }

  @override
  String toString() {
    return "FileItem(path: $path, type: $type, modified: $modified)";
  }

}