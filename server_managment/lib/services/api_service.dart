import 'package:dio/dio.dart';
import 'dart:io';
import 'package:device_info_plus/device_info_plus.dart';

class ApiService {
  final Dio _dio = Dio();
  final String baseUrl = "http://192.168.0.22:5000";
  final String apiKey = "APIKEY123";
  bool isInitialized = false;

  ApiService() {
    _dio.options.headers["X-API-KEY"] = apiKey;
  }

  Future<void> init() async {
    if (!isInitialized) {
      await _addDeviceIdHeader();
      isInitialized = true;
    }
  }

  Future<void> _addDeviceIdHeader() async {
    DeviceInfoPlugin deviceInfo = DeviceInfoPlugin();
    String? deviceId;

    if(Platform.isAndroid) {
      AndroidDeviceInfo androidInfo = await deviceInfo.androidInfo;
      deviceId = androidInfo.id;
    } else if(Platform.isWindows) {
      WindowsDeviceInfo windowsInfo = await deviceInfo.windowsInfo;
      deviceId = windowsInfo.deviceId;
    }

    if (deviceId != null) {
      _dio.options.headers["X-Device-ID"] = deviceId;
      print("Device ID set: $deviceId");
    } else {
      print("Could not retrieve device ID");
    }
  }

  Future<List<String>> getFiles({String folderPath = ""}) async {
    await init();
    try {
      final response = await _dio.get(
        "$baseUrl/list",
        queryParameters: {"folder": folderPath},
      );
      return List<String>.from(response.data["files"]);
    } catch (e) {
      print("Błąd podczas pobierania plików: $e");
      return [];
    }
  }

  Future<String> uploadFile(File file, String folder) async {
    await init();
    try {
      FormData formData = FormData.fromMap({
        "file": await MultipartFile.fromFile(file.path, filename: file.path.split("/").last),
        "folder": folder,
      });
      final response = await _dio.post("$baseUrl/upload", data: formData);
      return response.data["message"];
    } catch (e) {
      print("Błąd podczas wysyłania pliku: $e");
      return "Błąd: $e";
    }
  }

  Future<void> downloadFile(String filename, String savePath) async {
    await init();
    try {
      final directory = Directory(savePath).parent;
      if (!await directory.exists()) {
        await directory.create(recursive: true);
      }

      await _dio.download(
        "$baseUrl/download/$filename",
        savePath,
        onReceiveProgress: (received, total) {
          if (total != -1) {
            print("Postęp pobierania: ${(received / total * 100).toStringAsFixed(0)}%");
          }
        },
      );

      final file = File(savePath);
      if (await file.exists()) {
        print("Plik $filename został pomyślnie pobrany do $savePath");
      } else {
        throw Exception("Plik $filename nie został zapisany w $savePath");
      }
    } catch (e) {
      print("Błąd podczas pobierania pliku: $e");
      rethrow;
    }
  }

  Future<String> getServerVariable() async {
    await init();
    try {
      final response = await _dio.get("$baseUrl/get_variable");
      return response.data["server_variable"];
    } catch (e) {
      print("Błąd pobierania zmiennej: $e");
      return "Błąd: $e";
    }
  }

  Future<String> updateServerVariable(String newValue) async {
    await init();
    try {
      final response = await _dio.post(
        "$baseUrl/update_variable",
        data: {"new_value": newValue},
      );
      return response.data["message"];
    } catch (e) {
      print("Błąd aktualizacji zmiennej: $e");
      return "Błąd: $e";
    }
  }

  Future<String> getLogs() async {
    await init();
    try {
      final response = await _dio.get("$baseUrl/get_logs");
      return response.data["logs"];
    } catch (e) {
      print("Błąd pobierania logów: $e");
      return "Błąd: $e";
    }
  }
}