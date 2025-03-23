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
import 'package:server_managment/models/items_in_row.dart';

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
  int rowCount = 2;

  @override
  void initState() {
    super.initState();
    _initializeAndLoadFiles();
  }

  Future<void> _initializeAndLoadFiles() async {
    await widget.apiService.init();
    final itemsInRow = ItemsInRow();
    final count = itemsInRow.getItemsInRow();
    setState(() {
      rowCount = count;
    });
    _loadFiles();
  }

  bool isFolder(String path) => path.endsWith('/');

  void _loadFiles({String folderPath = ""}) async {
    final fileList = await widget.apiService.getFiles(folderPath: folderPath);
    setState(() {
      files = fileList;
      currentFolder = folderPath;
    });
  }

  void _uploadFile() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();
    if (result != null) {
      File file = File(result.files.single.path!);
      final message = await widget.apiService.uploadFile(file, currentFolder);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
      _loadFiles(folderPath: currentFolder);
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
    try {
      String savePath = await _getDownloadPath(filename);
      logger.i("Próba pobrania pliku: $filename do $savePath");
      final directory = Directory(savePath).parent;
      if (!await directory.exists()) {
        await directory.create(recursive: true);
      }

      await widget.apiService.downloadFile(filename, savePath);

      File downloadedFile = File(savePath);
      if (await downloadedFile.exists() && await downloadedFile.length() > 0) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text("Pobrano: ${filename.split('/').last}")),
        );
        final result = await OpenFile.open(savePath);
        if (result.type != ResultType.done) {
          if (!mounted) return;
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text("Nie można otworzyć pliku: ${result.message}")),
          );
        }
      } else {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text("Plik ${filename.split('/').last} nie został pobrany lub jest pusty")),
        );
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text("Błąd pobierania: $e")),
      );
    }
  }

  void _dowFile(String path) {
    if (!isFolder(path)) {
      _downloadFile(path);
    }
  }

  void _handleTap(String path) {
    if (isFolder(path)) {
      _loadFiles(folderPath: path);
    }
    else {
      _dowFile(path);
    }
  }

  Widget _getIcon(String path, [bool isImage = false, bool fullSize = false]) {
    final double size = fullSize ? 64 : 24;
    if (isFolder(path)) {
      return Filesicons.getIconForExtension("folder", size);
    }
    final extension = path.split('.').last.toLowerCase();
    if (isImage) {
      if (extension == "jpg" || extension == "jpeg" || extension == "png" || extension == "gif") {
        final baseUrl = dotenv.env['BASE_URL'] ?? '';
        final imageUrl = "$baseUrl/download/$path";
        return Image.network(
          imageUrl,
          fit: BoxFit.cover,
          width: double.infinity,
          headers: {
            "X-Api-Key": widget.apiService.apiKey,
            "X-Device-Id": widget.apiService.dio.options.headers["X-Device-Id"] as String? ?? "",
          },
          loadingBuilder: (context, child, loadingProgress) {
            if (loadingProgress == null) {
              return child;
            }
            return const Center(child: CircularProgressIndicator());
          },
          errorBuilder: (context, error, stackTrace) {
            logger.e("Błąd ładowania obrazu: $error");
            return Filesicons.getIconForExtension(extension, size);
          },
        );
      }
    }
    return Filesicons.getIconForExtension(extension, size);
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        Column(
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
                            : currentFolder.split('/').reversed.skip(1).toList().reversed.join('/');
                        _loadFiles(folderPath: parentFolder);
                      },
                    ),
                  Expanded(
                    child: Text(
                      currentFolder.isEmpty ? "My drive" : currentFolder,
                      style: const TextStyle(fontWeight: FontWeight.bold),
                    ),
                  ),
                ],
              ),
            ),
            Expanded(
              child: FutureBuilder<List<FileItem>>(
                future: widget.apiService.getFiles(folderPath: currentFolder),
                builder: (context, snapshot) {
                  if (snapshot.connectionState == ConnectionState.waiting) {
                    return const Center(child: CircularProgressIndicator());
                  }
                  if (snapshot.hasError) {
                    return const Center(child: Text('Błąd połączenia'));
                  }
                  final files = snapshot.data ?? [];
                  return GridView.builder(
                    gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
                      crossAxisCount: rowCount,
                      crossAxisSpacing: 10.0,
                      mainAxisSpacing: 10.0,
                      childAspectRatio: 1.0,
                    ),
                    itemCount: files.length,
                    itemBuilder: (context, index) {
                      final file = files[index];
                      String displayName = file.path.endsWith('/')
                          ? file.path.substring(0, file.path.length - 1).split('/').last
                          : file.path.split('/').last;

                      return GestureDetector(
                        onTap: () => _handleTap(file.path),
                        child: Padding(
                          padding: const EdgeInsets.all(2.0),
                          child: Card(
                            elevation: 2,
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Row(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Padding(
                                      padding: const EdgeInsets.only(right: 4.0, left: 4.0, top: 4.0),
                                      child: SizedBox(
                                        width: 20,
                                        height: 20,
                                        child: _getIcon(file.path),
                                      ),
                                    ),
                                    Expanded(
                                      child: Padding(
                                        padding: const EdgeInsets.only(top: 4.0),
                                        child: Text(
                                          displayName,
                                          textAlign: TextAlign.left,
                                          overflow: TextOverflow.ellipsis,
                                          maxLines: 1,
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                                Expanded(
                                  child: Padding(
                                    padding: const EdgeInsets.all(8.0),
                                    child: ClipRRect(
                                      borderRadius: BorderRadius.circular(8.0),
                                      child: _getIcon(file.path, true, true),
                                    ),
                                  ),
                                ),
                                /*if (!isFolder(file.path))
                                  IconButton(
                                    icon: const Icon(Icons.download, size: 20),
                                    onPressed: () => _dowFile(file.path),
                                  ),*/
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
          ],
        ),
        Positioned(
          bottom: 16,
          right: 16,
          child: FloatingActionButton(
            onPressed: _uploadFile,
            tooltip: 'Upload file',
            foregroundColor: Colors.black,
            backgroundColor: Colors.white,
            shape: CircleBorder(),
            child: const Icon(Icons.add),
          ),
        ),
      ],
    );
  }
}