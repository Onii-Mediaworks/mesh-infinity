import 'package:flutter/foundation.dart';

enum NavigationDestination {
  login,
  home,
  room,
  roomDetails,
  userProfile,
  settings,
  mediaViewer,
  search,
  createRoom,
  notifications,
}

class NavigationManager extends ChangeNotifier {
  final List<NavigationDestination> _path = [];
  NavigationDestination? _presentedSheet;
  NavigationDestination? _fullScreenCover;
  Map<String, dynamic> _arguments = {};

  List<NavigationDestination> get path => List.unmodifiable(_path);
  NavigationDestination? get presentedSheet => _presentedSheet;
  NavigationDestination? get fullScreenCover => _fullScreenCover;
  Map<String, dynamic> get arguments => Map.unmodifiable(_arguments);

  void navigateTo(NavigationDestination destination, {Map<String, dynamic>? args}) {
    _path.add(destination);
    if (args != null) {
      _arguments = args;
    }
    notifyListeners();
  }

  void navigateBack() {
    if (_path.isNotEmpty) {
      _path.removeLast();
      _arguments = {};
      notifyListeners();
    }
  }

  void navigateToRoot() {
    _path.clear();
    _arguments = {};
    notifyListeners();
  }

  void presentSheet(NavigationDestination destination, {Map<String, dynamic>? args}) {
    _presentedSheet = destination;
    if (args != null) {
      _arguments = args;
    }
    notifyListeners();
  }

  void dismissSheet() {
    _presentedSheet = null;
    _arguments = {};
    notifyListeners();
  }

  void presentFullScreenCover(NavigationDestination destination, {Map<String, dynamic>? args}) {
    _fullScreenCover = destination;
    if (args != null) {
      _arguments = args;
    }
    notifyListeners();
  }

  void dismissFullScreenCover() {
    _fullScreenCover = null;
    _arguments = {};
    notifyListeners();
  }
}
