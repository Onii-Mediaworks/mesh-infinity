// mnsp_server_config_screen.dart
//
// MnspServerConfigScreen — Remote Shell (MNSP) server settings
// (SPEC §22.54.6).
//
// WHAT THE USER SETS
// ------------------
//   Who can connect — the trust floor (never below Level 6) and the list of
//                     people with an explicit shell grant.  §20.3.1 makes
//                     shell access an explicit per-peer capability, so an
//                     empty list means nobody can connect, and the screen
//                     says so.
//   Per person      — the local OS account, allowed shells, allowed
//                     commands and starting folder, edited in a sheet.
//   Adapters        — the SSH adapter and the local sshd port.
//
// Removing a person revokes the grant on save (the backend ends any open
// session for that peer); the row's swipe-to-delete asks first.
//
// Reached from: Services → Hosting → Remote Shell → Configure.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/service_config_models.dart';
import '../../../core/widgets/focusable_tile.dart';
import '../services_state.dart';
import 'config_screen_shell.dart';
import 'config_validation.dart';
import 'contact_picker_sheet.dart';
import 'trust_floor_selector.dart';

/// Edits [MnspConfig] (§22.54.6).
class MnspServerConfigScreen extends StatefulWidget {
  const MnspServerConfigScreen({super.key});

  @override
  State<MnspServerConfigScreen> createState() => _MnspServerConfigScreenState();
}

class _MnspServerConfigScreenState extends State<MnspServerConfigScreen> {
  MnspConfig _loaded = const MnspConfig();
  MnspConfig _draft = const MnspConfig();
  ServiceHostFacts _facts = const ServiceHostFacts();

  final _port = TextEditingController(text: '22');

  bool _loading = true;
  String? _load_error;
  bool _saving = false;
  String? _save_error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _port.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _load_error = null;
    });
    final state = context.read<ServicesState>();
    final cfg = await state.fetch_mnsp_config();
    final facts = await state.host_facts();
    if (!mounted) return;
    setState(() {
      _loading = false;
      if (cfg == null) {
        _load_error = "Couldn't load service settings. Try again.";
      } else {
        _loaded = cfg;
        _draft = cfg;
        _facts = facts;
        _port.text = cfg.sshd_port.toString();
      }
    });
  }

  Future<void> _save() async {
    setState(() {
      _saving = true;
      _save_error = null;
    });
    final ok = await context.read<ServicesState>().save_mnsp_config(_draft);
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
        const SnackBar(content: Text('Remote Shell settings saved')),
      );
    }
  }

  void _update(MnspConfig next) => setState(() => _draft = next);

  /// "+ Add person": pick a contact at or above the floor, then open the
  /// per-person sheet with the §22.54.6 defaults.
  Future<void> _add_person() async {
    final peer = await pick_contact(
      context,
      floor: _draft.trust_floor,
      exclude: {for (final m in _draft.user_map) m.peer_id},
    );
    if (peer == null || !mounted) return;
    final shells = _facts.shells;
    final mapping = MnspUserMapping(
      peer_id: peer.id,
      display_name: peer.name,
      local_user: _facts.default_user,
      allowed_shells: shells.isEmpty ? const [] : [shells.first],
      allowed_commands: null,
      working_dir: _facts.home,
    );
    final edited = await _open_sheet(mapping);
    if (edited == null || !mounted) return;
    _update(_draft.copyWith(user_map: [..._draft.user_map, edited]));
  }

  Future<void> _edit_person(int index) async {
    final edited = await _open_sheet(_draft.user_map[index]);
    if (edited == null || !mounted) return;
    final next = [..._draft.user_map];
    next[index] = edited;
    _update(_draft.copyWith(user_map: next));
  }

  Future<MnspUserMapping?> _open_sheet(MnspUserMapping mapping) {
    return showModalBottomSheet<MnspUserMapping>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      showDragHandle: true,
      builder: (_) => PersonSheet(mapping: mapping, facts: _facts),
    );
  }

  /// §22.54.6: confirm before a grant is dropped.
  Future<bool> _confirm_remove(MnspUserMapping m) async {
    final remove = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Remove shell access for ${m.label}?'),
        content: const Text(
          'They can no longer open a shell on this device once you save.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Keep'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    return remove ?? false;
  }

  void _remove_at(int index) {
    final next = [..._draft.user_map]..removeAt(index);
    _update(_draft.copyWith(user_map: next));
  }

  String? get _port_error =>
      _draft.ssh_adapter ? validate_port(_port.text) : null;

  /// Every stored grant must still pass the sheet's rules.
  bool get _valid {
    if (_port_error != null) return false;
    for (final m in _draft.user_map) {
      if (person_errors(m, _facts).values.any((e) => e != null)) return false;
    }
    return true;
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;

    return ConfigScreenShell(
      title: 'Remote Shell',
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
            'Remote Shell (MNSP) lets the people you list here open a '
            'terminal on this device as a local account.',
            style: text.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
          ),
        ),
        ConfigGroup(
          title: 'Who can connect',
          children: [
            TrustFloorSelector(
              minimum: mnspFloor,
              value: _draft.trust_floor,
              protocol: 'Remote Shell',
              on_changed: (level) =>
                  _update(_draft.copyWith(trust_floor: level)),
            ),
            const SizedBox(height: 12),
            Text('Allowed people', style: text.bodyMedium),
            if (_draft.user_map.isEmpty)
              const HelperLine(
                'No one can open a shell yet. Add a person to grant access.',
              )
            else
              for (var i = 0; i < _draft.user_map.length; i++)
                Dismissible(
                  key: ValueKey(_draft.user_map[i].peer_id),
                  direction: DismissDirection.endToStart,
                  confirmDismiss: (_) => _confirm_remove(_draft.user_map[i]),
                  onDismissed: (_) => _remove_at(i),
                  background: Container(
                    alignment: Alignment.centerRight,
                    padding: const EdgeInsets.only(right: 16),
                    color: cs.errorContainer,
                    child: Icon(Icons.delete_outline, color: cs.onErrorContainer),
                  ),
                  child: FocusableTile(
                    on_secondary: () async {
                      if (await _confirm_remove(_draft.user_map[i]) &&
                          mounted) {
                        _remove_at(i);
                      }
                    },
                    child: ListTile(
                      minTileHeight: 48,
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.person_outline),
                      title: Text(_draft.user_map[i].label),
                      subtitle: Text(
                        'as ${_draft.user_map[i].local_user}',
                        style: mono_style(context).copyWith(fontSize: 12),
                      ),
                      trailing: person_errors(_draft.user_map[i], _facts)
                              .values
                              .any((e) => e != null)
                          ? Icon(Icons.error_outline, color: cs.error)
                          : const Icon(Icons.chevron_right),
                      onTap: () => _edit_person(i),
                    ),
                  ),
                ),
            TextButton.icon(
              onPressed: _add_person,
              icon: const Icon(Icons.person_add_alt_outlined),
              label: const Text('Add person'),
            ),
          ],
        ),
        ConfigGroup(
          title: 'Adapters',
          children: [
            SwitchListTile(
              title: const Text('SSH adapter'),
              value: _draft.ssh_adapter,
              onChanged: (v) => _update(_draft.copyWith(ssh_adapter: v)),
            ),
            const HelperLine(
              'Forwards mesh connections to the SSH server already running on this computer.',
            ),
            if (_draft.ssh_adapter)
              TextField(
                controller: _port,
                keyboardType: TextInputType.number,
                inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                decoration: InputDecoration(
                  labelText: 'sshd port',
                  errorText: _port_error,
                ),
                onChanged: (v) => _update(
                  _draft.copyWith(sshd_port: int.tryParse(v.trim()) ?? 0),
                ),
              ),
          ],
        ),
      ],
    );
  }
}

/// §22.54.6 per-person rules, keyed by field.  Shared by the list (to flag
/// a stale grant) and the sheet (to show the inline reason).
Map<String, String?> person_errors(
  MnspUserMapping m,
  ServiceHostFacts facts,
) {
  final user = m.local_user.trim();
  String? user_error;
  if (user.isEmpty) {
    user_error = 'Enter a local account';
  } else if (facts.users.isNotEmpty && !facts.users.contains(user)) {
    user_error = 'No local account called $user';
  }
  return {
    'local_user': user_error,
    'allowed_shells': m.allowed_shells.isEmpty ? 'Choose at least one shell' : null,
    'allowed_commands': (m.allowed_commands ?? const []).any(
          (c) => c.trim().isEmpty,
        )
        ? 'Each command line must have a command'
        : null,
    'working_dir': directory_exists(m.working_dir)
        ? null
        : "That folder doesn't exist",
  };
}

/// The per-person sheet (§22.54.6).
class PersonSheet extends StatefulWidget {
  const PersonSheet({super.key, required this.mapping, required this.facts});

  /// The grant being edited (new grants arrive with defaults filled).
  final MnspUserMapping mapping;

  /// OS users, shells and home folder for defaults and validation.
  final ServiceHostFacts facts;

  @override
  State<PersonSheet> createState() => _PersonSheetState();
}

class _PersonSheetState extends State<PersonSheet> {
  late MnspUserMapping _draft = widget.mapping;
  late final _user = TextEditingController(text: widget.mapping.local_user);
  late final _dir = TextEditingController(text: widget.mapping.working_dir);
  late final _commands = TextEditingController(
    text: (widget.mapping.allowed_commands ?? const []).join('\n'),
  );

  @override
  void dispose() {
    _user.dispose();
    _dir.dispose();
    _commands.dispose();
    super.dispose();
  }

  Map<String, String?> get _errors => person_errors(_draft, widget.facts);

  bool get _valid => _errors.values.every((e) => e == null);

  /// Shells to offer: the OS list plus anything already selected, so an
  /// existing grant never loses a shell the list no longer reports.
  List<String> get _shell_options => {
    ...widget.facts.shells,
    ..._draft.allowed_shells,
  }.toList();

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    final errors = _errors;
    final restricted = _draft.allowed_commands != null;

    return Padding(
      padding: EdgeInsets.only(
        bottom: MediaQuery.viewInsetsOf(context).bottom,
      ),
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(_draft.label, style: text.titleLarge),
            const SizedBox(height: 12),
            TextField(
              controller: _user,
              style: mono_style(context),
              autocorrect: false,
              decoration: InputDecoration(
                labelText: 'Local user account',
                errorText: errors['local_user'],
              ),
              onChanged: (v) =>
                  setState(() => _draft = _draft.copyWith(local_user: v)),
            ),
            const SizedBox(height: 16),
            Text('Allowed shells', style: text.bodyMedium),
            const SizedBox(height: 6),
            Wrap(
              spacing: 8,
              runSpacing: 4,
              children: [
                for (final shell in _shell_options)
                  FilterChip(
                    label: Text(shell, style: mono_style(context)),
                    selected: _draft.allowed_shells.contains(shell),
                    onSelected: (on) => setState(() {
                      final next = [..._draft.allowed_shells];
                      on ? next.add(shell) : next.remove(shell);
                      _draft = _draft.copyWith(allowed_shells: next);
                    }),
                  ),
              ],
            ),
            if (errors['allowed_shells'] != null)
              InlineError(errors['allowed_shells']!),
            const SizedBox(height: 12),
            Text('Allowed commands', style: text.bodyMedium),
            RadioGroup<bool>(
              groupValue: restricted,
              onChanged: (only_these) => setState(() {
                _draft = _draft.copyWith(
                  allowed_commands: only_these == true
                      ? _lines(_commands.text)
                      : null,
                );
              }),
              child: const Column(
                children: [
                  RadioListTile<bool>(
                    contentPadding: EdgeInsets.zero,
                    value: false,
                    title: Text('Any command'),
                  ),
                  RadioListTile<bool>(
                    contentPadding: EdgeInsets.zero,
                    value: true,
                    title: Text('Only these commands'),
                  ),
                ],
              ),
            ),
            if (restricted)
              TextField(
                controller: _commands,
                style: mono_style(context),
                maxLines: null,
                minLines: 3,
                autocorrect: false,
                decoration: InputDecoration(
                  labelText: 'One command per line',
                  errorText: errors['allowed_commands'],
                ),
                onChanged: (v) => setState(
                  () => _draft = _draft.copyWith(allowed_commands: _lines(v)),
                ),
              ),
            const SizedBox(height: 12),
            TextField(
              controller: _dir,
              style: mono_style(context),
              autocorrect: false,
              decoration: InputDecoration(
                labelText: 'Starting folder',
                errorText: errors['working_dir'],
              ),
              onChanged: (v) =>
                  setState(() => _draft = _draft.copyWith(working_dir: v)),
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: FilledButton(
                onPressed: _valid
                    ? () => Navigator.pop(
                        context,
                        _draft.copyWith(
                          local_user: _draft.local_user.trim(),
                          working_dir: _draft.working_dir.trim(),
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

  /// Split the editor text into command lines.  Blank lines are kept so the
  /// "each line non-empty" rule can flag them, except a single trailing
  /// newline, which every editor leaves behind.
  static List<String> _lines(String text) {
    final lines = text.split('\n');
    if (lines.length > 1 && lines.last.isEmpty) lines.removeLast();
    return lines;
  }
}
