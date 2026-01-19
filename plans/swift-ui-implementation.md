# Swift UI Implementation Plan

## Architecture Analysis from Android Reference

The Android reference UI uses a sophisticated architecture that we'll adapt for Swift:

### Key Components Analysis

#### 1. **Application Structure**
- **Android**: `ElementXApplication` extends `Application` and implements `DependencyInjectionGraphOwner`
- **Swift Equivalent**: `NetInfinityApp` with `@main` attribute and environment objects

#### 2. **Dependency Injection**
- **Android**: Uses **Metro** DI framework with `@DependencyGraph` annotations
- **Swift Equivalent**: Property-based injection with `DependencyContainer` protocol

#### 3. **Navigation**
- **Android**: Uses **Appyx** with `NodeHost`, `BackStack`, and navigation targets
- **Swift Equivalent**: `NavigationManager` with `NavigationPath` and `NavigationDestination` enum

#### 4. **State Management**
- **Android**: Uses **Molecule** for state flows and **Compose** for UI state
- **Swift Equivalent**: `ObservableObject` with `@Published` properties and Combine

#### 5. **UI Framework**
- **Android**: Jetpack Compose with `Composable` functions
- **Swift Equivalent**: SwiftUI with `View` structs and `@State`, `@Binding` properties

## Implementation Plan

### Phase 1: Core Architecture Adaptation ✅

**Status**: Already completed in previous work

- ✅ **App Entry Point**: `NetInfinityApp.swift` with main app structure
- ✅ **State Management**: `AppState.swift` with authentication states
- ✅ **Dependency Injection**: `DependencyContainer.swift` with service protocols
- ✅ **Navigation System**: `NavigationManager.swift` with path-based navigation
- ✅ **Root Navigation**: `RootView.swift` with authentication flow

### Phase 2: Authentication Flow Implementation

**Objective**: Adapt Android's authentication flow to Swift

**Android Components to Adapt**:
- `SignedOutEntryPoint` → `AuthenticationView.swift`
- `LoginParams` → `LoginParameters.swift`
- `SessionStore` → `SessionService.swift`

**Implementation Tasks**:
1. **Create Authentication Views**:
   - `LoginView.swift` - Email/password and SSO login
   - `OnboardingView.swift` - User onboarding flow
   - `ServerSelectionView.swift` - Homeserver selection

2. **Implement Authentication State Management**:
   ```swift
   enum AuthenticationState {
       case unknown
       case authenticated(session: Session)
       case notAuthenticated
       case onboardingRequired
   }
   ```

3. **Add Authentication Services**:
   ```swift
   protocol AuthenticationService {
       func login(email: String, password: String) async throws -> Session
       func loginWithSSO(provider: String) async throws -> Session
       func register(accountType: AccountType) async throws -> Session
       func restoreSession() async throws -> Session?
       func logout() async throws
   }
   ```

### Phase 3: Room Navigation Implementation

**Objective**: Implement room list and room navigation based on Android's `LoggedInFlowNode`

**Android Components to Adapt**:
- `LoggedInAppScopeFlowNode` → `MainTabView.swift`
- `RoomFlowNode` → `RoomView.swift`
- `JoinedRoomFlowNode` → `JoinedRoomView.swift`

**Implementation Tasks**:
1. **Create Room List Components**:
   - `RoomListView.swift` - Main room list with filtering
   - `RoomListViewModel.swift` - Room data management
   - `RoomRowView.swift` - Individual room list item

2. **Implement Room Navigation**:
   ```swift
   enum RoomNavigationDestination: Hashable {
       case room(roomId: String)
       case roomDetails(roomId: String)
       case roomSettings(roomId: String)
       case createRoom
       case search
   }
   ```

3. **Create Room View Components**:
   - `RoomView.swift` - Main room view with messages
   - `RoomHeaderView.swift` - Room title and actions
   - `MessageTimelineView.swift` - Message list
   - `RoomSettingsView.swift` - Room configuration

### Phase 4: Message Composer Implementation

**Objective**: Create message composer and timeline components

**Android Components to Adapt**:
- Message composer from room timeline → `MessageComposerView.swift`
- Message timeline → `MessageTimelineView.swift`

**Implementation Tasks**:
1. **Create Message Composer**:
   ```swift
   struct MessageComposerView: View {
       @State private var messageText = ""
       @State private var isEditing = false
       @State private var showAttachmentOptions = false
       
       let onSend: (String) -> Void
       let onAttachmentSelected: (AttachmentType) -> Void
       
       var body: some View {
           HStack {
               // Text input field
               // Attachment button
               // Send button
           }
       }
   }
   ```

2. **Implement Message Timeline**:
   ```swift
   struct MessageTimelineView: View {
       let messages: [Message]
       let currentUserId: String
       
       var body: some View {
           LazyVStack {
               ForEach(messages) { message in
                   MessageBubbleView(message: message, isCurrentUser: message.senderId == currentUserId)
               }
           }
       }
   }
   ```

3. **Create Message Types**:
   ```swift
   enum MessageType {
       case text(content: String)
       case image(url: URL, thumbnail: URL?)
       case video(url: URL, thumbnail: URL?)
       case file(name: String, url: URL, size: Int)
       case audio(url: URL, duration: TimeInterval)
       case system(content: String)
   }
   ```

### Phase 5: Media Viewing Implementation

**Objective**: Implement media viewing and gallery functionality

**Android Components to Adapt**:
- Media viewer components → `MediaViewerView.swift`
- Gallery components → `MediaGalleryView.swift`

**Implementation Tasks**:
1. **Create Media Viewer**:
   ```swift
   struct MediaViewerView: View {
       let mediaItems: [MediaItem]
       let initialIndex: Int
       @State private var currentIndex: Int
       
       var body: some View {
           TabView(selection: $currentIndex) {
               ForEach(mediaItems.indices, id: \.self) { index in
                   MediaItemView(item: mediaItems[index])
                       .tag(index)
               }
           }
           .tabViewStyle(.page(indexDisplayMode: .never))
       }
   }
   ```

2. **Implement Media Gallery**:
   ```swift
   struct MediaGalleryView: View {
       let mediaItems: [MediaItem]
       let onSelect: (MediaItem) -> Void
       
       var body: some View {
           LazyVGrid(columns: [GridItem(.adaptive(minimum: 100))]) {
               ForEach(mediaItems) { item in
                   MediaThumbnailView(item: item)
                       .onTapGesture { onSelect(item) }
               }
           }
       }
   }
   ```

3. **Add Media Services**:
   ```swift
   protocol MediaService {
       func uploadMedia(data: Data, type: MediaType) async throws -> MediaItem
       func downloadMedia(url: URL) async throws -> Data
       func getMediaThumbnail(url: URL, size: CGSize) async throws -> UIImage
   }
   ```

### Phase 6: Deep Linking and Notifications

**Objective**: Add push notification handling and deep link support

**Android Components to Adapt**:
- `IntentResolver` → `DeepLinkHandler.swift`
- Notification handling → `NotificationService.swift`

**Implementation Tasks**:
1. **Create Deep Link Handler**:
   ```swift
   enum DeepLinkType {
       case room(roomId: String, eventId: String?)
       case user(userId: String)
       case login(homeserver: String?)
       case settings
   }
   
   struct DeepLinkHandler {
       func handle(url: URL) -> DeepLinkType? {
           // Parse URL and return appropriate deep link type
       }
   }
   ```

2. **Implement Notification Service**:
   ```swift
   protocol NotificationService {
       func registerForPushNotifications() async throws
       func handlePushNotification(userInfo: [AnyHashable: Any])
       func scheduleLocalNotification(title: String, body: String, delay: TimeInterval)
   }
   ```

3. **Add App Delegate Integration**:
   ```swift
   class AppDelegate: NSObject, UIApplicationDelegate {
       func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey : Any]? = nil) -> Bool {
           // Setup notification handling
           return true
       }
       
       func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable : Any]) {
           // Handle push notifications
       }
       
       func application(_ application: UIApplication, continue userActivity: NSUserActivity, restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
           // Handle deep links
           return true
       }
   }
   ```

### Phase 7: Design System Implementation

**Objective**: Create design system with Compound-like components

**Android Components to Adapt**:
- Compound design system → `DesignSystem.swift`
- Theme management → `ThemeManager.swift`

**Implementation Tasks**:
1. **Create Design System Components**:
   ```swift
   struct ButtonStyles {
       static func primary() -> some View {
           // Primary button style
       }
       
       static func secondary() -> some View {
           // Secondary button style
       }
   }
   
   struct Typography {
       static let headline1: Font = .system(size: 32, weight: .bold)
       static let headline2: Font = .system(size: 24, weight: .bold)
       static let body: Font = .system(size: 16, weight: .regular)
       static let caption: Font = .system(size: 12, weight: .regular)
   }
   ```

2. **Implement Theme Management**:
   ```swift
   enum AppTheme: String, CaseIterable {
       case light
       case dark
       case system
   }
   
   struct ThemeManager {
       static func applyTheme(_ theme: AppTheme) {
           // Apply theme colors and styles
       }
       
       static func currentTheme() -> AppTheme {
           // Return current theme
       }
   }
   ```

3. **Create Reusable UI Components**:
   ```swift
   struct AvatarView: View {
       let url: URL?
       let size: CGFloat
       let placeholder: String
       
       var body: some View {
           // Avatar implementation
       }
   }
   
   struct BadgeView: View {
       let count: Int
       let style: BadgeStyle
       
       var body: some View {
           // Badge implementation
       }
   }
   ```

### Phase 8: Accessibility and Internationalization

**Objective**: Implement accessibility and internationalization support

**Implementation Tasks**:
1. **Add Accessibility Features**:
   ```swift
   struct AccessibleButton: View {
       let action: () -> Void
       let label: String
       
       var body: some View {
           Button(action: action) {
               Text(label)
           }
           .accessibilityLabel(label)
           .accessibilityHint("Double tap to activate")
           .accessibilityAddTraits(.isButton)
       }
   }
   ```

2. **Implement Internationalization**:
   ```swift
   enum Localization {
       static func localizedString(_ key: String) -> String {
           return NSLocalizedString(key, comment: "")
       }
       
       static func localizedString(_ key: String, arguments: [CVarArg]) -> String {
           return String(format: localizedString(key), arguments: arguments)
       }
   }
   ```

3. **Add Dynamic Type Support**:
   ```swift
   struct AdaptiveText: View {
       let text: String
       let style: Font.TextStyle
       
       var body: some View {
           Text(text)
               .font(.preferredFont(forTextStyle: style))
               .adjustsFontForContentSizeCategory(true)
       }
   }
   ```

### Phase 9: Testing Infrastructure

**Objective**: Add testing infrastructure and UI tests

**Implementation Tasks**:
1. **Create Unit Test Structure**:
   ```swift
   class RoomListViewModelTests: XCTestCase {
       func testLoadRooms() async {
           // Test room loading functionality
       }
       
       func testFilterRooms() {
           // Test room filtering
       }
   }
   ```

2. **Implement UI Tests**:
   ```swift
   class AuthenticationFlowTests: XCTestCase {
       func testLoginFlow() {
           let app = XCUIApplication()
           app.launch()
           
           // Test login flow
       }
   }
   ```

3. **Add Snapshot Testing**:
   ```swift
   class ComponentSnapshotTests: XCTestCase {
       func testMessageBubbleSnapshots() {
           let message = Message(text: "Hello", sender: "User")
           let view = MessageBubbleView(message: message)
           
           assertSnapshot(matching: view, as: .image)
       }
   }
   ```

### Phase 10: Documentation

**Objective**: Document the Swift UI architecture and implementation guide

**Implementation Tasks**:
1. **Update SPEC.md**: Add comprehensive Swift UI documentation
2. **Create Architecture Diagrams**: Add Mermaid diagrams for key components
3. **Write Implementation Guide**: Document best practices and patterns
4. **Add API Documentation**: Document public interfaces and protocols

## Architecture Mapping: Android → Swift

| **Android Component** | **Swift Equivalent** | **Status** |
|-----------------------|----------------------|------------|
| `ElementXApplication` | `NetInfinityApp` | ✅ Complete |
| `MainActivity` | `RootView` | ✅ Complete |
| `RootFlowNode` | `RootView` with auth states | ✅ Complete |
| `Appyx Navigation` | `NavigationManager` | ✅ Complete |
| `Metro DI` | `DependencyContainer` | ✅ Complete |
| `Molecule State` | `ObservableObject` | ✅ Complete |
| `Compose UI` | `SwiftUI` | ✅ Complete |
| `LoggedInFlowNode` | `MainTabView` | ⏳ Planned |
| `RoomFlowNode` | `RoomView` | ⏳ Planned |
| `Message Composer` | `MessageComposerView` | ⏳ Planned |
| `Media Viewer` | `MediaViewerView` | ⏳ Planned |
| `IntentResolver` | `DeepLinkHandler` | ⏳ Planned |
| `Compound Design` | `DesignSystem` | ⏳ Planned |

## Implementation Timeline

### Week 1: Core Architecture (✅ Complete)
- App structure and navigation
- State management and DI
- Authentication flow foundation

### Week 2: Room Navigation
- Room list implementation
- Room detail views
- Room navigation flow

### Week 3: Messaging Components
- Message composer
- Message timeline
- Message types and rendering

### Week 4: Media Features
- Media viewer
- Media gallery
- Media services

### Week 5: Advanced Features
- Deep linking
- Notifications
- Design system

### Week 6: Polish and Testing
- Accessibility
- Internationalization
- Testing infrastructure
- Documentation

## Key Technical Decisions

1. **State Management**: Use `ObservableObject` with `@Published` properties for reactive UI updates
2. **Navigation**: Use SwiftUI's `NavigationPath` for type-safe navigation
3. **Dependency Injection**: Use property-based injection with protocol-oriented design
4. **Concurrency**: Use `async/await` for all asynchronous operations
5. **Error Handling**: Use `Result` type and custom error types for comprehensive error management
6. **Testing**: Use XCTest for unit tests and XCUITest for UI tests

This implementation plan provides a comprehensive roadmap for adapting the Android reference UI to Swift while maintaining the architectural patterns and user experience of the original application.