import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:path_provider/path_provider.dart';
import 'package:server_managment/models/files_icons.dart';
import 'dart:io';
import 'package:server_managment/services/api_service.dart';
import 'package:open_file/open_file.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:logger/logger.dart';
import 'package:server_managment/models/file_item.dart';

enum PopUpMenuOptions { delete, rename, copy, move }

class PopUpMenu extends StatelessWidget {
  final Function(PopUpMenuOptions) onSelected;

  const PopUpMenu({super.key, required this.onSelected});

  @override
  Widget build(BuildContext context) {
    return PopupMenuButton<PopUpMenuOptions>(
      onSelected: onSelected,
      itemBuilder: (BuildContext context) => <PopupMenuEntry<PopUpMenuOptions>>[
        const PopupMenuItem<PopUpMenuOptions>(
          value: PopUpMenuOptions.delete,
          child: Row(
            children: [
              Icon(Icons.delete),
              SizedBox(width: 8),
              Text('Delete'),
            ],
          ),
        ),
        const PopupMenuItem<PopUpMenuOptions>(
          value: PopUpMenuOptions.rename,
          child: Row(
            children: [
              Icon(Icons.edit),
              SizedBox(width: 8),
              Text('Rename'),
            ],
          ),
        ),
        const PopupMenuItem<PopUpMenuOptions>(
          value: PopUpMenuOptions.copy,
          child: Row(
            children: [Icon(Icons.copy), SizedBox(width: 8), Text('Copy')],
          ),
        ),
        const PopupMenuItem<PopUpMenuOptions>(
          value: PopUpMenuOptions.move,
          child: Row(
            children: [
              Icon(Icons.move_to_inbox),
              SizedBox(width: 8),
              Text('Move'),
            ],
          ),
        ),
      ],
    );
  }
}

class FilesExplorerPage extends StatefulWidget {
  final ApiService apiService;

  const FilesExplorerPage({super.key, required this.apiService});

  @override
  FilesExplorerPageState createState() => FilesExplorerPageState();
}

class FilesExplorerPageState extends State<FilesExplorerPage> {
  List<FileItem> files = [];
  String currentFolder = "";
  final Logger logger = Logger();
  bool isLoading = false;
  Map<String, double> downloadProgress = {};
  double? _uploadProgress;

  @override
  void initState() {
    super.initState();
    _initializeAndLoadFiles();
  }

  Future<void> _initializeAndLoadFiles() async {
    await widget.apiService.init();
    await _loadFiles();
  }

  bool isFolder(String path) => path.endsWith('/');

  Future<void> _loadFiles({String folderPath = ""}) async {
    if (isLoading) return;
    setState(() => isLoading = true);
    try {
      final fileList = await widget.apiService.getFiles(folderPath: folderPath);
      if (!mounted) return;
      setState(() {
        files = fileList;
        currentFolder = folderPath;
      });
    } finally {
      if (mounted) setState(() => isLoading = false);
    }
  }

  void _uploadFile() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();
    if (result != null) {
      File file = File(result.files.single.path!);

      setState(() {
        _uploadProgress = 0.0;
      });

      try {
        final message = await widget.apiService.uploadFile(
          file,
          currentFolder,
          onSendProgress: (sent, total) {
            if (mounted) {
              setState(() {
                _uploadProgress = sent / total;
              });
            }
          },
        );
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context)
              .showSnackBar(SnackBar(content: Text("Błąd wysyłania: $e")));
        }
      } finally {
        if (mounted) {
          setState(() {
            _uploadProgress = null;
          });
        }
      }

      await _loadFiles(folderPath: currentFolder);
    }
  }

  Future<String> _getDownloadPath(String filename) async {
    String sanitizedFilename = filename.split('/').last;
    String downloadPath;

    if (Platform.isAndroid) {
      if (await Permission.storage.request().isGranted ||
          await Permission.manageExternalStorage.request().isGranted) {
        downloadPath = "/storage/emulated/0/Download/$sanitizedFilename";
      } else {
        throw Exception("Brak uprawnień do zapisu w folderze Pobrane");
      }
    } else if (Platform.isWindows) {
      String? userDir = Platform.environment['USERPROFILE'];
      if (userDir == null) {
        throw Exception("Nie można znaleźć folderu użytkownika");
      }
      downloadPath = "$userDir\\Downloads\\$sanitizedFilename";
    } else {
      Directory dir = await getApplicationDocumentsDirectory();
      downloadPath = "${dir.path}/$sanitizedFilename";
    }
    return downloadPath;
  }

  void _downloadFile(String filename) async {
    setState(() => downloadProgress[filename] = 0.0);

    try {
      String savePath = await _getDownloadPath(filename);
      logger.i("Próba pobrania pliku: $filename do $savePath");
      final directory = Directory(savePath).parent;
      if (!await directory.exists()) await directory.create(recursive: true);

      await widget.apiService.downloadFile(
        filename,
        savePath,
        onProgress: (received, total) {
          if (total != -1 && mounted) {
            setState(() => downloadProgress[filename] = received / total);
          }
        },
      );

      File downloadedFile = File(savePath);
      if (await downloadedFile.exists() && await downloadedFile.length() > 0) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text("Pobrano: ${filename.split('/').last}")),
        );
        final result = await OpenFile.open(savePath);
        if (result.type != ResultType.done && mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text("Nie można otworzyć pliku: ${result.message}"),
            ),
          );
        }
      } else if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              "Plik ${filename.split('/').last} nie został pobrany lub jest pusty",
            ),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text("Błąd pobierania: $e")));
      }
    } finally {
      if (mounted) setState(() => downloadProgress.remove(filename));
    }
  }

  void _dowFile(String path) {
    if (!isFolder(path)) _downloadFile(path);
  }

  void _handleTap(String path) {
    if (isFolder(path)) {
      _loadFiles(folderPath: path);
    } else {
      _dowFile(path);
    }
  }

  void _handleMenuSelection(String path, PopUpMenuOptions option) {
    switch (option) {
      case PopUpMenuOptions.delete:
        ApiService().deleteFile(path);
        _loadFiles(folderPath: currentFolder);
        break;
      case PopUpMenuOptions.rename:
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text("Rename $path - nie zaimplementowane")),
        );
        break;
      case PopUpMenuOptions.copy:
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text("Copy $path - nie zaimplementowane")),
        );
        break;
      case PopUpMenuOptions.move:
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text("Move $path - nie zaimplementowane")),
        );
        break;
    }
  }

  Widget _getIcon(String path, [bool isImage = false, bool fullSize = false]) {
  final double size = fullSize ? 64 : 24;
  if (isFolder(path)) return Filesicons.getIconForExtension("folder", size);

  final extension = path.split('.').last.toLowerCase();
  if (isImage && ["jpg", "jpeg", "png", "gif"].contains(extension)) {
    final baseUrl = dotenv.env["BASE_URL"] ?? "";
    final imageUrl = "$baseUrl/download/$path";
    final token = widget.apiService.dio.options.headers["Authorization"] as String? ?? "";
    return Image.network(
      imageUrl,
      fit: BoxFit.cover,
      width: double.infinity,
      headers: {
        "X-Api-Key": widget.apiService.apiKey,
        "X-Device-Id": widget.apiService.dio.options.headers["X-Device-Id"] as String? ?? "",
        "Authorization": token,
      },
      loadingBuilder: (context, child, loadingProgress) {
        return loadingProgress == null
            ? child
            : const Center(child: CircularProgressIndicator());
      },
      errorBuilder: (context, error, stackTrace) {
        logger.e("Błąd ładowania obrazu: $error");
        return Filesicons.getIconForExtension(extension, size);
      },
    );
  }
  return Filesicons.getIconForExtension(extension, size);
}

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(8.0),
            child: Row(
              children: [
                if (currentFolder.isNotEmpty)
                  IconButton(
                    icon: const Icon(Icons.arrow_back),
                    onPressed: () {
                      final parentFolder = currentFolder.endsWith('/')
                          ? currentFolder
                              .substring(0, currentFolder.length - 1)
                              .split('/')
                              .reversed
                              .skip(1)
                              .toList()
                              .reversed
                              .join('/')
                          : currentFolder
                              .split('/')
                              .reversed
                              .skip(1)
                              .toList()
                              .reversed
                              .join('/');
                      _loadFiles(folderPath: parentFolder);
                    },
                  ),
                Expanded(
                  child: Text(
                    currentFolder.isEmpty ? "My drive" : currentFolder,
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.add),
                  onPressed: _uploadFile,
                ),
              ],
            ),
          ),
          Expanded(
            child: isLoading
                ? const Center(child: CircularProgressIndicator())
                : LayoutBuilder(
                    builder: (context, constraints) {
                      return GridView.builder(
                        gridDelegate: const SliverGridDelegateWithMaxCrossAxisExtent(
                          maxCrossAxisExtent: 250,
                          crossAxisSpacing: 10.0,
                          mainAxisSpacing: 10.0,
                          childAspectRatio: 1.0,
                        ),
                        itemCount: files.length,
                        itemBuilder: (context, index) {
                          final file = files[index];
                          String normalizedPath = file.path.replaceAll('\\', '/');
                          String displayName = normalizedPath.endsWith('/')
                              ? normalizedPath
                                  .substring(0, normalizedPath.length - 1)
                                  .split('/')
                                  .last
                              : normalizedPath.split("/").last;

                          return GestureDetector(
                            onTap: () => _handleTap(file.path),
                            child: Padding(
                              padding: const EdgeInsets.all(2.0),
                              child: Card(
                                elevation: 2,
                                child: Stack(
                                  children: [
                                    Column(
                                      mainAxisAlignment: MainAxisAlignment.center,
                                      children: [
                                        Row(
                                          mainAxisAlignment:
                                              MainAxisAlignment.center,
                                          children: [
                                            Padding(
                                              padding: const EdgeInsets.only(
                                                right: 4.0,
                                                left: 4.0,
                                                top: 4.0,
                                              ),
                                              child: SizedBox(
                                                width: 20,
                                                height: 20,
                                                child: _getIcon(file.path),
                                              ),
                                            ),
                                            Expanded(
                                              child: Padding(
                                                padding: const EdgeInsets.only(
                                                  top: 4.0,
                                                ),
                                                child: Text(
                                                  displayName,
                                                  textAlign: TextAlign.left,
                                                  overflow: TextOverflow.ellipsis,
                                                  maxLines: 1,
                                                ),
                                              ),
                                            ),
                                            const Spacer(),
                                            PopUpMenu(
                                              onSelected: (option) =>
                                                  _handleMenuSelection(
                                                file.path,
                                                option,
                                              ),
                                            ),
                                          ],
                                        ),
                                        Expanded(
                                          child: Padding(
                                            padding: const EdgeInsets.all(8.0),
                                            child: ClipRRect(
                                              borderRadius:
                                                  BorderRadius.circular(8.0),
                                              child: _getIcon(file.path, true, true),
                                            ),
                                          ),
                                        ),
                                        if (downloadProgress.containsKey(file.path))
                                          Padding(
                                            padding: const EdgeInsets.symmetric(
                                              horizontal: 8.0,
                                            ),
                                            child: Column(
                                              children: [
                                                LinearProgressIndicator(
                                                  value: downloadProgress[file.path],
                                                  minHeight: 4,
                                                  backgroundColor: Colors.grey[300],
                                                  valueColor:
                                                      const AlwaysStoppedAnimation<
                                                              Color>(
                                                          Colors.blue),
                                                ),
                                                const SizedBox(height: 4),
                                                Text(
                                                  '${(downloadProgress[file.path]! * 100).toStringAsFixed(1)}%',
                                                  style: const TextStyle(
                                                    fontSize: 12,
                                                  ),
                                                ),
                                              ],
                                            ),
                                          ),
                                      ],
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          );
                        },
                      );
                    },
                  ),
          ),
          if (_uploadProgress != null)
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: Column(
                children: [
                  LinearProgressIndicator(
                    value: _uploadProgress,
                    minHeight: 6,
                    backgroundColor: Colors.grey[300],
                    valueColor:
                        const AlwaysStoppedAnimation<Color>(Colors.green),
                  ),
                  const SizedBox(height: 4),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Text(
                        'Uploading: ',
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Text(
                        '${(_uploadProgress! * 100).toStringAsFixed(1)}%',
                        style: const TextStyle(fontSize: 14),
                      ),
                    ],
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}