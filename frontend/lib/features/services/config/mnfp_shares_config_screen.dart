// mnfp_shares_config_screen.dart
//
// MnfpSharesConfigScreen — File Access (MNFP) shares and adapters
// (SPEC §22.54.7).
//
// WHAT THE USER SETS
// ------------------
//   Shares   — one card per shared folder: name, root path (monospace),
//              access, floors, per-contact exceptions, hidden flag.  The
//              share sheet edits one share; deleting asks first because
//              contacts lose access the moment the change is saved.
//   Adapters — SMB / NFS bridges, and SFTP via the Remote Shell SSH
//              adapter, which is only offered while that adapter is on.
//
// Rules the sheet enforces inline: name 1–64 and unique, folder exists and
// is not the app's own data folder (the backend re-checks readability and
// the vault rule on save), write floor at least the read floor.
//
// Reached from: Services → Hosting → File Access → Configure.

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/peer_models.dart';
import '../../../backend/models/service_config_models.dart';
import '../../../core/widgets/empty_state.dart';
import '../../../core/widgets/focusable_tile.dart';
import '../../peers/peers_state.dart';
import '../services_state.dart';
import 'config_screen_shell.dart';
import 'config_validation.dart';
import 'contact_picker_sheet.dart';
import 'trust_floor_selector.dart';

/// Edits [MnfpConfig] (§22.54.7).
class MnfpSharesConfigScreen extends StatefulWidget {
  const MnfpSharesConfigScreen({super.key});

  @override
  State<MnfpSharesConfigScreen> createState() => _MnfpSharesConfigScreenState();
}

class _MnfpSharesConfigScreenState extends State<MnfpSharesConfigScreen> {
  MnfpConfig _loaded = const MnfpConfig();
  MnfpConfig _draft = const MnfpConfig();

  /// Whether Remote Shell's SSH adapter is on (gates SFTP via SSH).
  bool _ssh_on = false;

  bool _loading = true;
  String? _load_error;
  bool _saving = false;
  String? _save_error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _load_error = null;
    });
    final state = context.read<ServicesState>();
    final cfg = await state.fetch_mnfp_config();
    final mnsp = await state.fetch_mnsp_config();
    if (!mounted) return;
    setState(() {
      _loading = false;
      if (cfg == null) {
        _load_error = "Couldn't load service settings. Try again.";
      } else {
        _loaded = cfg;
        _draft = cfg;
        _ssh_on = mnsp?.ssh_adapter ?? false;
      }
    });
  }

  Future<void> _save() async {
    setState(() {
      _saving = true;
      _save_error = null;
    });
    final ok = await context.read<ServicesState>().save_mnfp_config(_draft);
    if (!mounted) return;
    setState(() {
      _saving = false;
      if (ok) {
        _loaded = _draft;
      } else {
        _save_error = saveFailedText;
      }
    });
    if (ok) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('File Access settings saved')),
      );
    }
  }

  void _update(MnfpConfig next) => setState(() => _draft = next);

  /// Open the share sheet for a new share or to edit [index].
  Future<void> _edit(int? index) async {
    final existing = index == null ? null : _draft.shares[index];
    final peers = context.read<PeersState>();
    final result = await showModalBottomSheet<MnfpShare>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      showDragHandle: true,
      builder: (_) => ChangeNotifierProvider<PeersState>.value(
        value: peers,
        child: ShareSheet(
          share: existing,
          taken_names: {
            for (var i = 0; i < _draft.shares.length; i++)
              if (i != index) _draft.shares[i].name.trim().toLowerCase(),
          },
        ),
      ),
    );
    if (result == null || !mounted) return;
    final next = [..._draft.shares];
    if (index == null) {
      next.add(result);
    } else {
      next[index] = result;
    }
    _update(_draft.copyWith(shares: next));
  }

  /// §22.54.7: confirm before a share is dropped.
  Future<void> _remove(int index) async {
    final share = _draft.shares[index];
    final stop = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Stop sharing ${share.name}?'),
        content: const Text(
          'Contacts lose access immediately; nothing on your disk is deleted.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Keep sharing'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Stop sharing'),
          ),
        ],
      ),
    );
    if (stop != true || !mounted) return;
    final next = [..._draft.shares]..removeAt(index);
    _update(_draft.copyWith(shares: next));
  }

  /// Every stored share must still pass the sheet's rules.
  bool get _valid {
    final names = <String>{};
    for (final s in _draft.shares) {
      if (validate_name(s.name) != null) return false;
      if (!names.add(s.name.trim().toLowerCase())) return false;
      if (s.root_path.trim().isEmpty) return false;
      if (s.min_trust_level < mnfpFloor || s.min_trust_level > trustMax) {
        return false;
      }
      if (s.write_trust_level < s.min_trust_level) return false;
    }
    if (_draft.sftp_via_ssh && !_ssh_on) return false;
    return true;
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;

    return ConfigScreenShell(
      title: 'File Access',
      loading: _loading,
      load_error: _load_error,
      on_retry_load: _load,
      dirty: _draft != _loaded,
      valid: _valid,
      saving: _saving,
      save_error: _save_error,
      on_save: _save,
      children: [
        Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: Text(
            'File Access (MNFP) lets contacts open the folders you share '
            'here. Nothing outside these folders is reachable.',
            style: text.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
          ),
        ),
        Text('Shares', style: text.titleSmall),
        const SizedBox(height: 8),
        if (_draft.shares.isEmpty)
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 16),
            child: EmptyState(
              icon: Icons.folder_shared_outlined,
              title: 'Nothing is shared yet.',
              body: 'Add a folder to share it with contacts.',
            ),
          )
        else
          for (var i = 0; i < _draft.shares.length; i++)
            _ShareCard(
              share: _draft.shares[i],
              on_edit: () => _edit(i),
              on_remove: () => _remove(i),
            ),
        SizedBox(
          height: 48,
          child: FilledButton.tonalIcon(
            onPressed: () => _edit(null),
            icon: const Icon(Icons.add),
            label: const Text('Add share'),
          ),
        ),
        const SizedBox(height: 16),
        ConfigGroup(
          title: 'Adapters',
          children: [
            SwitchListTile(
              title: const Text('SMB'),
              value: _draft.smb_adapter,
              onChanged: (v) => _update(_draft.copyWith(smb_adapter: v)),
            ),
            const HelperLine(
              'Lets existing Windows and Samba file clients reach this computer through the mesh.',
            ),
            SwitchListTile(
              title: const Text('NFS'),
              value: _draft.nfs_adapter,
              onChanged: (v) => _update(_draft.copyWith(nfs_adapter: v)),
            ),
            const HelperLine(
              'Lets existing NFS clients reach this computer through the mesh.',
            ),
            SwitchListTile(
              title: const Text('SFTP via SSH'),
              value: _draft.sftp_via_ssh,
              onChanged: _ssh_on
                  ? (v) => _update(_draft.copyWith(sftp_via_ssh: v))
                  : null,
            ),
            HelperLine(
              _ssh_on
                  ? 'Reuses the Remote Shell SSH adapter for file transfer.'
                  : 'Turn on the SSH adapter in Remote Shell first',
            ),
          ],
        ),
      ],
    );
  }
}

/// One share in the list: name, root path, access and floor.
class _ShareCard extends StatelessWidget {
  const _ShareCard({
    required this.share,
    required this.on_edit,
    required this.on_remove,
  });

  final MnfpShare share;
  final VoidCallback on_edit;
  final VoidCallback on_remove;

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    final floor = share.min_trust_level.clamp(0, trustMax);
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: FocusableTile(
        radius: 12,
        on_secondary: on_remove,
        child: ListTile(
          minTileHeight: 48,
          leading: Icon(
            share.hidden ? Icons.folder_off_outlined : Icons.folder_outlined,
          ),
          title: Text(share.name),
          subtitle: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                share.root_path,
                style: mono_style(context).copyWith(fontSize: 12),
                overflow: TextOverflow.ellipsis,
              ),
              Text(
                '${share.access.label} · Level $floor '
                '(${trustLevelNames[floor]}) and up'
                '${share.hidden ? ' · not listed' : ''}',
                style: text.bodySmall,
              ),
            ],
          ),
          isThreeLine: true,
          trailing: IconButton(
            icon: const Icon(Icons.delete_outline),
            tooltip: 'Stop sharing ${share.name}',
            onPressed: on_remove,
          ),
          onTap: on_edit,
        ),
      ),
    );
  }
}

/// The share sheet (§22.54.7): name, folder, access, floors, exceptions.
class ShareSheet extends StatefulWidget {
  const ShareSheet({super.key, required this.share, required this.taken_names});

  /// The share being edited, or null for a new one.
  final MnfpShare? share;

  /// Lower-cased names already in use, to refuse duplicates.
  final Set<String> taken_names;

  @override
  State<ShareSheet> createState() => _ShareSheetState();
}

class _ShareSheetState extends State<ShareSheet> {
  final _name = TextEditingController();
  final _path = TextEditingController();

  /// Whether the user has typed a name; otherwise it follows the folder.
  bool _name_touched = false;

  MnfpAccess _access = MnfpAccess.readOnly;
  int _read_floor = mnfpFloor;
  int _write_floor = mnfpWriteDefault;
  List<MnfpPeerOverride> _overrides = const [];
  bool _hidden = false;

  @override
  void initState() {
    super.initState();
    final s = widget.share;
    if (s != null) {
      _name.text = s.name;
      _name_touched = true;
      _path.text = s.root_path;
      _access = s.access;
      _read_floor = s.min_trust_level;
      _write_floor = s.write_trust_level;
      _overrides = s.peer_overrides;
      _hidden = s.hidden;
    }
  }

  @override
  void dispose() {
    _name.dispose();
    _path.dispose();
    super.dispose();
  }

  /// Platform folder picker (§22.54.7); the path field stays editable so
  /// desktop users can also paste a path.
  Future<void> _pick_folder() async {
    final chosen = await FilePicker.platform.getDirectoryPath();
    if (chosen == null || !mounted) return;
    _set_path(chosen);
  }

  void _set_path(String path) {
    setState(() {
      _path.text = path;
      if (!_name_touched) _name.text = folder_name(path);
    });
  }

  String? get _name_error {
    final base = validate_name(_name.text);
    if (base != null) return base;
    if (widget.taken_names.contains(_name.text.trim().toLowerCase())) {
      return 'You already have a share called ${_name.text.trim()}';
    }
    return null;
  }

  String? get _path_error {
    if (_path.text.trim().isEmpty) return 'Choose a folder';
    if (!directory_exists(_path.text)) return "That folder doesn't exist";
    return null;
  }

  String? get _write_error =>
      _access.allows_write && _write_floor < _read_floor
      ? 'Must be at least the read level'
      : null;

  bool get _valid =>
      _name_error == null && _path_error == null && _write_error == null;

  Future<void> _add_exception() async {
    final peer = await pick_contact(
      context,
      floor: mnfpFloor,
      exclude: {for (final o in _overrides) o.peer_id},
    );
    if (peer == null || !mounted) return;
    final access = await _choose_access(peer, MnfpAccess.readOnly);
    if (access == null || !mounted) return;
    setState(() {
      _overrides = [
        ..._overrides,
        MnfpPeerOverride(
          peer_id: peer.id,
          display_name: peer.name,
          access: access,
        ),
      ];
    });
  }

  /// Ask which access an exception grants.
  Future<MnfpAccess?> _choose_access(PeerModel peer, MnfpAccess current) {
    return showDialog<MnfpAccess>(
      context: context,
      builder: (ctx) => SimpleDialog(
        title: Text('Access for ${peer.name.isEmpty ? peer.id : peer.name}'),
        children: [
          for (final a in MnfpAccess.values)
            SimpleDialogOption(
              onPressed: () => Navigator.pop(ctx, a),
              child: Text(a.label),
            ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;

    return Padding(
      padding: EdgeInsets.only(
        bottom: MediaQuery.viewInsetsOf(context).bottom,
      ),
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              widget.share == null ? 'Add share' : 'Edit share',
              style: text.titleLarge,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _path,
              style: mono_style(context),
              autocorrect: false,
              decoration: InputDecoration(
                labelText: 'Folder',
                errorText: _path_error,
                suffixIcon: IconButton(
                  tooltip: 'Choose folder',
                  icon: const Icon(Icons.folder_open_outlined),
                  onPressed: _pick_folder,
                ),
              ),
              onChanged: _set_path,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _name,
              decoration: InputDecoration(
                labelText: 'Name',
                errorText: _name_error,
              ),
              onChanged: (_) => setState(() => _name_touched = true),
            ),
            const SizedBox(height: 16),
            Text('Access', style: text.bodyMedium),
            const SizedBox(height: 6),
            SegmentedButton<MnfpAccess>(
              segments: [
                for (final a in MnfpAccess.values)
                  ButtonSegment(value: a, label: Text(a.label)),
              ],
              selected: {_access},
              onSelectionChanged: (set) => setState(() => _access = set.first),
            ),
            const HelperLine(
              'The most a contact can do in this folder. Exceptions below can '
              'give one person more or less.',
            ),
            const SizedBox(height: 12),
            TrustFloorSelector(
              minimum: mnfpFloor,
              value: _read_floor,
              label: 'Read floor',
              protocol: 'File Access',
              on_changed: (level) => setState(() => _read_floor = level),
            ),
            if (_access.allows_write) ...[
              const SizedBox(height: 16),
              TrustFloorSelector(
                minimum: mnfpFloor,
                value: _write_floor,
                label: 'Write floor',
                protocol: 'File Access',
                error: _write_error,
                on_changed: (level) => setState(() => _write_floor = level),
              ),
            ],
            const SizedBox(height: 16),
            Text('Exceptions', style: text.bodyMedium),
            for (var i = 0; i < _overrides.length; i++)
              ListTile(
                minTileHeight: 48,
                contentPadding: EdgeInsets.zero,
                title: Text(_overrides[i].label),
                subtitle: Text(_overrides[i].access.label),
                trailing: IconButton(
                  icon: const Icon(Icons.close),
                  tooltip: 'Remove exception',
                  onPressed: () => setState(() {
                    _overrides = [..._overrides]..removeAt(i);
                  }),
                ),
                onTap: () async {
                  final o = _overrides[i];
                  final access = await _choose_access(
                    PeerModel(id: o.peer_id, name: o.display_name),
                    o.access,
                  );
                  if (access == null || !mounted) return;
                  setState(() {
                    final next = [..._overrides];
                    next[i] = MnfpPeerOverride(
                      peer_id: o.peer_id,
                      display_name: o.display_name,
                      access: access,
                    );
                    _overrides = next;
                  });
                },
              ),
            TextButton.icon(
              onPressed: _add_exception,
              icon: const Icon(Icons.person_add_alt_outlined),
              label: const Text('Add exception'),
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text("Don't list this share"),
              subtitle: const Text(
                'Contacts must know the name to open it.',
              ),
              value: _hidden,
              onChanged: (v) => setState(() => _hidden = v),
            ),
            const SizedBox(height: 8),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: FilledButton(
                onPressed: _valid
                    ? () => Navigator.pop(
                        context,
                        MnfpShare(
                          name: _name.text.trim(),
                          root_path: _path.text.trim(),
                          access: _access,
                          min_trust_level: _read_floor,
                          write_trust_level: _access.allows_write
                              ? _write_floor
                              : (_write_floor < _read_floor
                                    ? _read_floor
                                    : _write_floor),
                          peer_overrides: _overrides,
                          hidden: _hidden,
                        ),
                      )
                    : null,
                child: const Text('Done'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
