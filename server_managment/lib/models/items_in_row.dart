import 'dart:io';

class ItemsInRow {
  String deviceType;

  ItemsInRow() : deviceType = Platform.isAndroid ? "Mobile" : "Desktop";

  int getItemsInRow() {
    if (deviceType == "Mobile") {
      return 2;
    }
    return 5;
  }
}