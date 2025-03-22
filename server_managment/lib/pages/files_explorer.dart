import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:server_managment/models/files_icons.dart';
import 'dart:io';
import 'package:server_managment/services/api_service.dart';
import 'package:open_file/open_file.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:logger/logger.dart';

class FilesExplorerPage extends StatefulWidget {
  final ApiService apiService;

  const FilesExplorerPage({super.key, required this.apiService});

  @override
  FilesExplorerPageState createState() => FilesExplorerPageState();
}

class FilesExplorerPageState extends State<FilesExplorerPage> {
  List<String> files = [];
  String currentFolder = "";
  final Logger logger = Logger();

  @override
  void initState() {
    super.initState();
    _initializeAndLoadFiles();
    _loadFiles();
  }

  Future<void> _initializeAndLoadFiles() async {
    await widget.apiService.init();
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
    if (!isFolder(path)){
      _downloadFile(path);
    }
  }

  void _handleTap(String path) {
    if (isFolder(path)) {
      _loadFiles(folderPath: path);
    }
  }

  Widget _getIcon(String path) {
    if (isFolder(path)) {
      return Filesicons.getIconForExtension("folder");
    }
    final extension = path.split('.').last.toLowerCase();
    return Filesicons.getIconForExtension(extension);
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
              child: FutureBuilder<List<String>>(
                future: widget.apiService.getFiles(folderPath: currentFolder),
                builder: (context, snapshot) {
                  if (snapshot.connectionState == ConnectionState.waiting) {
                    return const Center(child: CircularProgressIndicator());
                  }
                  if (snapshot.hasError) {
                    return const Center(child: Text('Błąd połączenia'));
                  }
                  final files = snapshot.data ?? [];
                  return ListView.builder(
                    itemCount: files.length,
                    itemBuilder: (context, index) {
                      final file = files[index];
                      String displayName = file.endsWith('/')
                          ? file.substring(0, file.length - 1).split('/').last
                          : file.split('/').last;
                      return ListTile(
                        leading: _getIcon(file),
                        title: Text(displayName),
                        subtitle: Text(file),
                        onTap: () => _handleTap(file),
                        trailing: !isFolder(file) ? IconButton(
                          icon: const Icon(Icons.download),
                          onPressed: () => _dowFile(file),
                        ) : null,
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