// print_service_config_screen.dart
//
// PrintServiceConfigScreen — Print Services settings (SPEC §22.54.9).
//
// WHAT THE USER SETS
// ------------------
// A list of shared printers, one per IPP queue.  "+ Share a printer" opens
// the printer sheet, which lists the queues the local spooler reports and
// offers "Other…" for a queue by URL.  Each printer has a name shown to
// contacts, a trust floor (never below Level 5) and read-only capability
// chips discovered from the queue, with a refresh button.
//
// URL rule: `ipp://`, `ipps://` or `http(s)://` to this device or the
// local network — the same locality rule the API Gateway applies, so the
// adapter cannot be pointed at the internet.
//
// Reached from: Services → Hosting → Print Services → Configure.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/service_config_models.dart';
import '../../../core/widgets/empty_state.dart';
import '../../../core/widgets/focusable_tile.dart';
import '../services_state.dart';
import 'config_screen_shell.dart';
import 'config_validation.dart';
import 'trust_floor_selector.dart';

/// Edits [PrintConfig] (§22.54.9).
class PrintServiceConfigScreen extends StatefulWidget {
  const PrintServiceConfigScreen({super.key});

  @override
  State<PrintServiceConfigScreen> createState() =>
      _PrintServiceConfigScreenState();
}

class _PrintServiceConfigScreenState extends State<PrintServiceConfigScreen> {
  PrintConfig _loaded = const PrintConfig();
  PrintConfig _draft = const PrintConfig();
  ServiceHostFacts _facts = const ServiceHostFacts();

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
    final cfg = await state.fetch_print_config();
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
      }
    });
  }

  Future<void> _save() async {
    setState(() {
      _saving = true;
      _save_error = null;
    });
    final ok = await context.read<ServicesState>().save_print_config(_draft);
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
        const SnackBar(content: Text('Print Services settings saved')),
      );
    }
  }

  /// Open the printer sheet for a new printer or to edit [index].
  Future<void> _edit(int? index) async {
    final existing = index == null ? null : _draft.printers[index];
    final result = await showModalBottomSheet<SharedPrinter>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      showDragHandle: true,
      builder: (_) => ChangeNotifierProvider<ServicesState>.value(
        value: context.read<ServicesState>(),
        child: PrinterSheet(
          printer: existing,
          hostname: _facts.hostname,
          taken_urls: {
            for (var i = 0; i < _draft.printers.length; i++)
              if (i != index) _draft.printers[i].ipp_url.trim().toLowerCase(),
          },
        ),
      ),
    );
    if (result == null || !mounted) return;
    final next = [..._draft.printers];
    if (index == null) {
      next.add(result);
    } else {
      next[index] = result;
    }
    setState(() => _draft = _draft.copyWith(printers: next));
  }

  /// Remove a printer from the draft (takes effect on save).
  void _remove(int index) {
    final next = [..._draft.printers]..removeAt(index);
    setState(() => _draft = _draft.copyWith(printers: next));
  }

  /// Whether every stored printer still passes its rules.
  bool get _valid => _draft.printers.every(
    (p) =>
        validate_printer_url(p.ipp_url, _facts.hostname) == null &&
        validate_name(p.printer_name) == null &&
        p.min_trust_level >= printFloor &&
        p.min_trust_level <= trustMax,
  );

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;

    return ConfigScreenShell(
      title: 'Print Services',
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
            'Print Services (IPP) lets contacts print to printers this '
            'device can reach.',
            style: text.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
          ),
        ),
        if (_draft.printers.isEmpty)
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 24),
            child: EmptyState(
              icon: Icons.print_outlined,
              title: 'No printers shared yet.',
              body: 'Share a printer to let contacts print to it.',
            ),
          )
        else
          for (var i = 0; i < _draft.printers.length; i++)
            _PrinterCard(
              printer: _draft.printers[i],
              on_edit: () => _edit(i),
              on_remove: () => _remove(i),
            ),
        SizedBox(
          height: 48,
          child: FilledButton.tonalIcon(
            onPressed: () => _edit(null),
            icon: const Icon(Icons.add),
            label: const Text('Share a printer'),
          ),
        ),
      ],
    );
  }
}

/// One shared printer in the list: name, queue URL (monospace), floor.
class _PrinterCard extends StatelessWidget {
  const _PrinterCard({
    required this.printer,
    required this.on_edit,
    required this.on_remove,
  });

  final SharedPrinter printer;
  final VoidCallback on_edit;
  final VoidCallback on_remove;

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: FocusableTile(
        radius: 12,
        on_secondary: on_remove,
        child: ListTile(
          minTileHeight: 48,
          leading: const Icon(Icons.print_outlined),
          title: Text(printer.printer_name),
          subtitle: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                printer.ipp_url,
                style: mono_style(context).copyWith(fontSize: 12),
                overflow: TextOverflow.ellipsis,
              ),
              Text(
                'Level ${printer.min_trust_level} '
                '(${trustLevelNames[printer.min_trust_level.clamp(0, trustMax)]}) and up'
                '${printer.capabilities.isEmpty ? '' : ' · ${printer.capabilities.join(', ')}'}',
                style: text.bodySmall,
              ),
            ],
          ),
          isThreeLine: true,
          trailing: IconButton(
            icon: const Icon(Icons.delete_outline),
            tooltip: 'Stop sharing ${printer.printer_name}',
            onPressed: on_remove,
          ),
          onTap: on_edit,
        ),
      ),
    );
  }
}

/// The printer sheet (§22.54.9): queue picker, name, floor, capabilities.
class PrinterSheet extends StatefulWidget {
  const PrinterSheet({
    super.key,
    required this.printer,
    required this.hostname,
    required this.taken_urls,
  });

  /// The printer being edited, or null for a new one.
  final SharedPrinter? printer;

  /// This machine's hostname for the locality rule.
  final String? hostname;

  /// Lower-cased URLs already shared, to refuse duplicates.
  final Set<String> taken_urls;

  @override
  State<PrinterSheet> createState() => _PrinterSheetState();
}

class _PrinterSheetState extends State<PrinterSheet> {
  /// Queues the spooler reported; null while loading.
  List<PrintQueue>? _queues;

  /// Index into [_queues]; [other] for "Other…"; null until the user picks.
  int? _picked;

  /// Sentinel for the "Other…" entry, which reveals the URL field.
  static const int other = -1;

  final _url = TextEditingController();
  final _name = TextEditingController();
  int _floor = printFloor;
  List<String> _capabilities = const [];

  /// True while the refresh button probes the queue.
  bool _probing = false;

  /// Message from the last failed probe.
  String? _probe_error;

  @override
  void initState() {
    super.initState();
    final p = widget.printer;
    if (p != null) {
      _url.text = p.ipp_url;
      _name.text = p.printer_name;
      _floor = p.min_trust_level;
      _capabilities = p.capabilities;
    }
    _load_queues();
  }

  @override
  void dispose() {
    _url.dispose();
    _name.dispose();
    super.dispose();
  }

  Future<void> _load_queues() async {
    final queues = await context.read<ServicesState>().print_queues();
    if (!mounted) return;
    setState(() {
      _queues = queues;
      // Editing an existing printer: pre-select its queue when listed.
      // With nothing listed, or a URL the spooler does not know, go
      // straight to the URL field.
      final current = _url.text.trim().toLowerCase();
      final match = queues.indexWhere((q) => q.url.toLowerCase() == current);
      if (match >= 0) {
        _picked = match;
      } else if (queues.isEmpty || widget.printer != null) {
        _picked = other;
      } else {
        _picked = null;
      }
    });
  }

  /// Apply a picked queue's URL, name default and capabilities.
  void _pick(int? index) {
    setState(() {
      _picked = index;
      if (index != null && index != other) {
        final q = _queues![index];
        _url.text = q.url;
        if (_name.text.trim().isEmpty) _name.text = q.name;
        _capabilities = q.capabilities;
      }
    });
  }

  /// Re-read the queue's name and capabilities.
  Future<void> _probe() async {
    setState(() {
      _probing = true;
      _probe_error = null;
    });
    final state = context.read<ServicesState>();
    final queue = await state.probe_print_queue(_url.text.trim());
    if (!mounted) return;
    setState(() {
      _probing = false;
      if (queue == null) {
        _probe_error = state.last_error() ?? "Couldn't reach the printer.";
      } else {
        _capabilities = queue.capabilities;
        if (_name.text.trim().isEmpty) _name.text = queue.name;
      }
    });
  }

  String? get _url_error {
    final base = validate_printer_url(_url.text, widget.hostname);
    if (base != null) return base;
    if (widget.taken_urls.contains(_url.text.trim().toLowerCase())) {
      return 'This printer is already shared';
    }
    return null;
  }

  String? get _name_error => validate_name(_name.text);

  bool get _valid => _url_error == null && _name_error == null;

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    final queues = _queues ?? const <PrintQueue>[];

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
              widget.printer == null ? 'Share a printer' : 'Edit printer',
              style: text.titleLarge,
            ),
            const SizedBox(height: 12),
            // Picker: queues the spooler reported, plus "Other…".
            DropdownMenu<int>(
              initialSelection: _picked,
              label: const Text('Printer'),
              expandedInsets: EdgeInsets.zero,
              enabled: _queues != null,
              onSelected: _pick,
              dropdownMenuEntries: [
                for (var i = 0; i < queues.length; i++)
                  DropdownMenuEntry<int>(value: i, label: queues[i].name),
                const DropdownMenuEntry<int>(value: other, label: 'Other…'),
              ],
            ),
            if (_queues != null && queues.isEmpty)
              const HelperLine(
                'No printer queues were found on this device. Enter the '
                'queue address below.',
              ),
            if (_picked == other) ...[
              const SizedBox(height: 12),
              TextField(
                controller: _url,
                style: mono_style(context),
                keyboardType: TextInputType.url,
                autocorrect: false,
                decoration: InputDecoration(
                  labelText: 'Queue address',
                  helperText: 'Example: ipp://127.0.0.1:631/printers/office',
                  errorText: _url_error,
                ),
                onChanged: (_) => setState(() {}),
              ),
            ],
            const SizedBox(height: 12),
            TextField(
              controller: _name,
              decoration: InputDecoration(
                labelText: 'Name shown to contacts',
                errorText: _name_error,
              ),
              onChanged: (_) => setState(() {}),
            ),
            const SizedBox(height: 16),
            TrustFloorSelector(
              minimum: printFloor,
              value: _floor,
              label: 'Who can print',
              protocol: 'Print Services',
              on_changed: (level) => setState(() => _floor = level),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Text('Capabilities', style: text.bodyMedium),
                const Spacer(),
                IconButton(
                  tooltip: 'Refresh capabilities',
                  onPressed: _probing || _url_error != null ? null : _probe,
                  icon: _probing
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.refresh),
                ),
              ],
            ),
            if (_capabilities.isEmpty)
              const HelperLine('Nothing discovered yet.')
            else
              Wrap(
                spacing: 8,
                runSpacing: 4,
                children: [
                  for (final cap in _capabilities) Chip(label: Text(cap)),
                ],
              ),
            if (_probe_error != null) InlineError(_probe_error!),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: FilledButton(
                onPressed: _valid
                    ? () => Navigator.pop(
                        context,
                        SharedPrinter(
                          ipp_url: _url.text.trim(),
                          printer_name: _name.text.trim(),
                          min_trust_level: _floor,
                          capabilities: _capabilities,
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
