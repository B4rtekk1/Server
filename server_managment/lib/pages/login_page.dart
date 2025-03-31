import 'package:flutter/material.dart';
import 'package:server_managment/services/api_service.dart';

class LoginPage extends StatefulWidget {
  final ApiService apiService;
  final Function onLoginSuccess;

  const LoginPage({super.key, required this.apiService, required this.onLoginSuccess});

  @override
  LoginPageState createState() => LoginPageState();
}

class LoginPageState extends State<LoginPage> {
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();
  String? _errorMessage;

  Future<void> _login() async {
    final success = await widget.apiService.login(
      _usernameController.text,
      _passwordController.text,
    );
    if (success) {
      if(mounted){
      widget.onLoginSuccess();
      Navigator.pushNamedAndRemoveUntil(context, "/home", (route)=>false);
      }
    } else {
      setState(() {
        _errorMessage = 'Incorrect username or password';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Login')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            TextField(
              controller: _usernameController,
              decoration: const InputDecoration(labelText: 'Username or Email'),
            ),
            TextField(
              controller: _passwordController,
              decoration: const InputDecoration(labelText: 'Password'),
              obscureText: true,
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _login,
              child: const Text('Login'),
            ),
            const SizedBox(height: 10),
            TextButton(
              onPressed: () {
                Navigator.pushNamed(context, '/register');
              },
              child: const Text('Don\'t have an account? Register'),
            ),
            if (_errorMessage != null)
              Padding(
                padding: const EdgeInsets.only(top: 10),
                child: Text(_errorMessage!, style: const TextStyle(color: Colors.red)),
              ),
          ],
        ),
      ),
    );
  }
}