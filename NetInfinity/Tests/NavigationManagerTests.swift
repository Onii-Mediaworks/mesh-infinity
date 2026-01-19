//
//  NavigationManagerTests.swift
//  NetInfinityTests
//
//

import XCTest
import Combine
@testable import NetInfinity

// MARK: - Navigation Manager Tests

class NavigationManagerTests: XCTestCase {
    
    var navigationManager: NavigationManager!
    var cancellables: Set<AnyCancellable>!
    
    override func setUp() {
        super.setUp()
        navigationManager = NavigationManager()
        cancellables = Set<AnyCancellable>()
    }
    
    override func tearDown() {
        navigationManager = nil
        cancellables = nil
        super.tearDown()
    }
    
    // MARK: - Navigation Path Tests
    
    func testInitialNavigationPathIsEmpty() {
        XCTAssertTrue(navigationManager.path.isEmpty, "Initial navigation path should be empty")
    }
    
    func testNavigateToDestination() {
        let expectation = XCTestExpectation(description: "Navigation path should contain destination")
        
        navigationManager.$path
            .sink { path in
                if !path.isEmpty {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.navigate(to: .home)
        
        wait(for: [expectation], timeout: 1.0)
        XCTAssertEqual(navigationManager.path.count, 1, "Navigation path should contain 1 destination")
    }
    
    func testNavigateBack() {
        navigationManager.navigate(to: .home)
        navigationManager.navigate(to: .settings)
        
        XCTAssertEqual(navigationManager.path.count, 2, "Navigation path should contain 2 destinations")
        
        navigationManager.navigateBack()
        
        XCTAssertEqual(navigationManager.path.count, 1, "Navigation path should contain 1 destination after navigating back")
    }
    
    func testNavigateToRoot() {
        navigationManager.navigate(to: .home)
        navigationManager.navigate(to: .settings)
        navigationManager.navigate(to: .room(roomId: "test"))
        
        XCTAssertEqual(navigationManager.path.count, 3, "Navigation path should contain 3 destinations")
        
        navigationManager.navigateToRoot()
        
        XCTAssertTrue(navigationManager.path.isEmpty, "Navigation path should be empty after navigating to root")
    }
    
    // MARK: - Sheet Navigation Tests
    
    func testPresentSheet() {
        let expectation = XCTestExpectation(description: "Sheet should be presented")
        
        navigationManager.$presentedSheet
            .sink { sheet in
                if sheet != nil {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.presentSheet(.bugReport)
        
        wait(for: [expectation], timeout: 1.0)
        XCTAssertNotNil(navigationManager.presentedSheet, "Sheet should be presented")
    }
    
    func testDismissSheet() {
        navigationManager.presentSheet(.bugReport)
        XCTAssertNotNil(navigationManager.presentedSheet, "Sheet should be presented")
        
        navigationManager.dismissSheet()
        XCTAssertNil(navigationManager.presentedSheet, "Sheet should be dismissed")
    }
    
    // MARK: - Full Screen Cover Tests
    
    func testPresentFullScreenCover() {
        let expectation = XCTestExpectation(description: "Full screen cover should be presented")
        
        navigationManager.$fullScreenCover
            .sink { cover in
                if cover != nil {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.presentFullScreenCover(.mediaViewer(mediaId: "test"))
        
        wait(for: [expectation], timeout: 1.0)
        XCTAssertNotNil(navigationManager.fullScreenCover, "Full screen cover should be presented")
    }
    
    func testDismissFullScreenCover() {
        navigationManager.presentFullScreenCover(.mediaViewer(mediaId: "test"))
        XCTAssertNotNil(navigationManager.fullScreenCover, "Full screen cover should be presented")
        
        navigationManager.dismissFullScreenCover()
        XCTAssertNil(navigationManager.fullScreenCover, "Full screen cover should be dismissed")
    }
    
    // MARK: - Convenience Method Tests
    
    func testNavigateToRoom() {
        let expectation = XCTestExpectation(description: "Should navigate to room")
        
        navigationManager.$path
            .sink { path in
                if path.count == 1, case .room = path.last {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.navigateToRoom("test-room")
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    func testNavigateToUserProfile() {
        let expectation = XCTestExpectation(description: "Should navigate to user profile")
        
        navigationManager.$path
            .sink { path in
                if path.count == 1, case .userProfile = path.last {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.navigateToUserProfile("test-user")
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    func testNavigateToSettings() {
        let expectation = XCTestExpectation(description: "Should select settings tab")
        
        navigationManager.$selectedTab
            .sink { tab in
                if tab == .settings && self.navigationManager.path.isEmpty {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.navigateToSettings()
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    // MARK: - Authentication Flow Tests
    
    func testNavigateToLogin() {
        let expectation = XCTestExpectation(description: "Should reset navigation to login root")
        
        navigationManager.$path
            .sink { path in
                if path.isEmpty {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.navigateToLogin()
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    func testNavigateToOnboarding() {
        let expectation = XCTestExpectation(description: "Should navigate to onboarding")
        
        navigationManager.$path
            .sink { path in
                if path.count == 1, case .onboarding = path.last {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.navigateToOnboarding()
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    func testNavigateToHome() {
        let expectation = XCTestExpectation(description: "Should reset navigation and select chats tab")
        
        navigationManager.$selectedTab
            .sink { tab in
                if tab == .chats && self.navigationManager.path.isEmpty {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.navigateToHome()
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    // MARK: - RootFlowNode Method Tests
    
    func testSwitchToLoggedInFlow() {
        let expectation = XCTestExpectation(description: "Should switch to chats tab on login")
        
        navigationManager.$selectedTab
            .sink { tab in
                if tab == .chats && self.navigationManager.path.isEmpty {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.switchToLoggedInFlow(sessionId: "test-session", navId: 1)
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    func testSwitchToNotLoggedInFlow() {
        let expectation = XCTestExpectation(description: "Should reset navigation for not logged in flow")
        
        navigationManager.$path
            .sink { path in
                if path.isEmpty {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.switchToNotLoggedInFlow()
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    func testSwitchToSignedOutFlow() {
        let expectation = XCTestExpectation(description: "Should switch to signed out flow")
        
        navigationManager.$path
            .sink { path in
                if path.count == 1, case .signedOutFlow = path.last {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.switchToSignedOutFlow(sessionId: "test-session")
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    func testNavigateToAccountSelect() {
        let expectation = XCTestExpectation(description: "Should navigate to account select")
        
        navigationManager.$path
            .sink { path in
                if path.count == 1, case .accountSelect = path.last {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.navigateToAccountSelect(currentSessionId: "test-session")
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    // MARK: - Intent Handling Tests
    
    func testHandleIntentWithURL() {
        let expectation = XCTestExpectation(description: "Should handle intent with URL")
        
        navigationManager.$path
            .sink { path in
                if path.count == 1, case .deepLink = path.last {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        let intent = Intent(url: URL(string: "https://netinfinity.local/test")!)
        navigationManager.handleIntent(intent)
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    func testNavigateToPermalinkData() {
        let expectation = XCTestExpectation(description: "Should navigate to permalink data")
        
        navigationManager.$path
            .sink { path in
                if path.count == 1, case .room = path.last {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        let permalinkData = PermalinkData.room(roomId: "test-room", eventId: nil, threadId: nil)
        navigationManager.navigateTo(permalinkData: permalinkData)
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    // MARK: - Utility Navigation Tests
    
    func testNavigateToBugReport() {
        let expectation = XCTestExpectation(description: "Should present bug report sheet")
        
        navigationManager.$presentedSheet
            .sink { sheet in
                if case .bugReport = sheet {
                    expectation.fulfill()
                }
            }
            .store(in: &cancellables)
        
        navigationManager.navigateToBugReport()
        
        wait(for: [expectation], timeout: 1.0)
    }
    
    func testDismissBugReport() {
        navigationManager.navigateToBugReport()
        XCTAssertNotNil(navigationManager.presentedSheet, "Bug report sheet should be presented")
        
        navigationManager.dismissBugReport()
        XCTAssertNil(navigationManager.presentedSheet, "Bug report sheet should be dismissed")
    }
}
