import 'models/room_models.dart';
import 'models/message_models.dart';
import 'models/peer_models.dart';
import 'models/file_transfer_models.dart';
import 'models/settings_models.dart';

sealed class BackendEvent {
  const BackendEvent();

  static BackendEvent? fromJson(Map<String, dynamic> json) {
    final type = json['type'] as String?;
    final data = json['data'];
    try {
      return switch (type) {
        'MessageAdded' => MessageAddedEvent(
          MessageModel.fromJson(data as Map<String, dynamic>),
        ),
        'RoomUpdated' => RoomUpdatedEvent(
          RoomSummary.fromJson(data as Map<String, dynamic>),
        ),
        'RoomDeleted' => RoomDeletedEvent(data['roomId'] as String),
        'MessageDeleted' => MessageDeletedEvent(
          roomId: data['roomId'] as String,
          messageId: data['messageId'] as String,
        ),
        'PeerUpdated' => PeerUpdatedEvent(
          PeerModel.fromJson(data as Map<String, dynamic>),
        ),
        'TransferUpdated' => TransferUpdatedEvent(
          FileTransferModel.fromJson(data as Map<String, dynamic>),
        ),
        'SettingsUpdated' => SettingsUpdatedEvent(
          SettingsModel.fromJson(data as Map<String, dynamic>),
        ),
        'ActiveRoomChanged' => ActiveRoomChangedEvent(
          data['roomId'] as String?,
        ),
        'TrustUpdated' => TrustUpdatedEvent(
          peerId: data['peerId'] as String,
          trustLevel: TrustLevel.fromInt(data['trustLevel'] as int),
        ),
        _ => null,
      };
    } catch (_) {
      return null;
    }
  }
}

final class MessageAddedEvent extends BackendEvent {
  const MessageAddedEvent(this.message);
  final MessageModel message;
}

final class RoomUpdatedEvent extends BackendEvent {
  const RoomUpdatedEvent(this.room);
  final RoomSummary room;
}

final class RoomDeletedEvent extends BackendEvent {
  const RoomDeletedEvent(this.roomId);
  final String roomId;
}

final class MessageDeletedEvent extends BackendEvent {
  const MessageDeletedEvent({required this.roomId, required this.messageId});
  final String roomId;
  final String messageId;
}

final class PeerUpdatedEvent extends BackendEvent {
  const PeerUpdatedEvent(this.peer);
  final PeerModel peer;
}

final class TransferUpdatedEvent extends BackendEvent {
  const TransferUpdatedEvent(this.transfer);
  final FileTransferModel transfer;
}

final class SettingsUpdatedEvent extends BackendEvent {
  const SettingsUpdatedEvent(this.settings);
  final SettingsModel settings;
}

final class ActiveRoomChangedEvent extends BackendEvent {
  const ActiveRoomChangedEvent(this.roomId);
  final String? roomId;
}

final class TrustUpdatedEvent extends BackendEvent {
  const TrustUpdatedEvent({required this.peerId, required this.trustLevel});
  final String peerId;
  final TrustLevel trustLevel;
}
