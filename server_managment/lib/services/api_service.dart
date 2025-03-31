import 'package:dio/dio.dart';
import 'dart:io';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:logger/logger.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:server_managment/models/file_item.dart';
import 'package:shared_preferences/shared_preferences.dart';

class ApiService {
  final Dio dio = Dio();
  late final String baseUrl;
  late final String apiKey;
  bool isInitialized = false;
  static Logger logger = Logger();

  ApiService() {
    baseUrl = dotenv.env["BASE_URL"] ?? '';
    apiKey = dotenv.env["API_KEY"] ?? '';

    if (baseUrl.isEmpty || apiKey.isEmpty) {
      logger.e("Environment variables are not set");
      throw Exception("Environment variables are not set");
    }

    dio.options.headers["X-API-KEY"] = apiKey;
  }

  Future<void> init() async {
    if (!isInitialized) {
      await _addDeviceIdHeader();
      await _addTokenHeader();
      isInitialized = true;
    }
  }

  Future<void> _addDeviceIdHeader() async {
    DeviceInfoPlugin deviceInfo = DeviceInfoPlugin();
    String? deviceId;

    if (Platform.isAndroid) {
      AndroidDeviceInfo androidInfo = await deviceInfo.androidInfo;
      deviceId = androidInfo.id;
    } else if (Platform.isWindows) {
      WindowsDeviceInfo windowsInfo = await deviceInfo.windowsInfo;
      deviceId = windowsInfo.deviceId;
    }

    if (deviceId != null) {
      dio.options.headers["X-Device-ID"] = deviceId;
      logger.i("Device ID set: $deviceId");
    } else {
      logger.e("Could not retrieve device ID");
    }
  }

  Future<void> _addTokenHeader() async {
    final prefs = await SharedPreferences.getInstance();
    final token = prefs.getString('token');
    if (token != null) {
      dio.options.headers["Authorization"] = "Bearer $token";
      logger.i("Token set in headers");
    }
  }

  Future<bool> login(String identifier, String password) async {
    try {
      final response = await dio.post(
        "$baseUrl/login",
        data: {"identifier": identifier, "password": password},
        options: Options(headers: {"Content-Type": "application/json"}),
      );
      if (response.statusCode == 200) {
        final token = response.data["token"];
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('token', token);
        dio.options.headers["Authorization"] = "Bearer $token";
        logger.i("Login successful, token saved");
        return true;
      }
      return false;
    } catch (e) {
      logger.e("Login failed: $e");
      return false;
    }
  }

  Future<void> logout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('token');
    dio.options.headers.remove("Authorization");
    isInitialized = false;
    logger.i("Logged out");
  }

  Future<bool> register(String username, String password, String email) async {
    try {
      final response = await dio.post(
        "$baseUrl/register",
        data: {"username": username, "password": password, "email": email},
        options: Options(headers: {"Content-Type": "application/json"}),
      );
      if (response.statusCode == 200 || response.statusCode == 201) {
        logger.i("Registration successful for $username");
        return true;
      }
      return false;
    } catch (e) {
      logger.e("Registration failed: $e");
      return false;
    }
  }

  Future<bool> verifyEmailCode(String email, String code) async {
    try {
      final response = await dio.post(
        "$baseUrl/verify-email",
        data: {"email": email, "code": code},
        options: Options(headers: {"Content-Type": "application/json"}),
      );
      if (response.statusCode == 200) {
        logger.i("Email $email verified successfully");
        return true;
      }
      return false;
    } on DioException catch (e) {
      logger.e(
        "Email verification failed: ${e.response?.data['error'] ?? e.message}",
      );
      throw Exception(
        "Verification failed: ${e.response?.data['error'] ?? e.message}",
      );
    }
  }

  Future<List<FileItem>> getFiles({String folderPath = ""}) async {
    await init();
    try {
      final response = await dio.get(
        "$baseUrl/list",
        queryParameters: {"folder": folderPath},
      );
      final filesJson = response.data["files"] as List<dynamic>;
      return filesJson
          .map((json) => FileItem.fromJSON(json as Map<String, dynamic>))
          .toList();
    } catch (e) {
      logger.e("Błąd podczas pobierania plików: $e");
      return [];
    }
  }

  Future<String> uploadFile(
    File file,
    String folder, {
    Function(int sent, int total)? onSendProgress,
  }) async {
    await init();
    try {
      FormData formData = FormData.fromMap({
        "file": await MultipartFile.fromFile(
          file.path,
          filename: file.path.split("/").last,
        ),
        "folder": folder,
      });
      final response = await dio.post(
        "$baseUrl/upload",
        data: formData,
        onSendProgress: onSendProgress,
      );
      logger.d(response.data["message"]);
      return response.data["message"];
    } catch (e) {
      logger.i("Błąd podczas wysyłania pliku: $e");
      return "Błąd: $e";
    }
  }

  Future<void> downloadFile(
    String filename,
    String savePath, {
    Function(int received, int total)? onProgress,
  }) async {
    await init();
    try {
      final directory = Directory(savePath).parent;
      if (!await directory.exists()) {
        await directory.create(recursive: true);
      }

      await dio.download(
        "$baseUrl/download/$filename",
        savePath,
        onReceiveProgress: onProgress,
      );

      final file = File(savePath);
      if (await file.exists()) {
        logger.i("Plik $filename został pomyślnie pobrany do $savePath");
      } else {
        throw Exception("Plik $filename nie został zapisany w $savePath");
      }
    } catch (e) {
      logger.e("Błąd podczas pobierania pliku: $e");
      rethrow;
    }
  }

  Future<String> getServerVariable() async {
    await init();
    try {
      final response = await dio.get("$baseUrl/get_variable");
      return response.data["server_variable"];
    } catch (e) {
      logger.e("Błąd pobierania zmiennej: $e");
      return "Błąd: $e";
    }
  }

  Future<String> updateServerVariable(String newValue) async {
    await init();
    try {
      final response = await dio.post(
        "$baseUrl/update_variable",
        data: {"new_value": newValue},
      );
      return response.data["message"];
    } catch (e) {
      logger.e("Błąd aktualizacji zmiennej: $e");
      return "Błąd: $e";
    }
  }

  Future<String> getLogs() async {
    await init();
    try {
      final response = await dio.get("$baseUrl/get_logs");
      return response.data["logs"];
    } catch (e) {
      logger.e("Błąd pobierania logów: $e");
      return "Błąd: $e";
    }
  }

  Future<String> deleteFile(String filename) async {
    await init();
    try {
      final response = await dio.delete(
        "$baseUrl/delete/$filename",
        data: {"filename": filename},
      );
      return response.data["message"];
    } catch (e) {
      logger.e("Błąd podczas usuwania pliku: $e");
      return "Błąd: $e";
    }
  }
}
