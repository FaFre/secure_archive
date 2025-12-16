import 'dart:io';

import 'package:fancy_password_field/fancy_password_field.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hooks/flutter_hooks.dart';
import 'package:flutter_material_design_icons/flutter_material_design_icons.dart';
import 'package:intl/intl.dart';
import 'package:path/path.dart' as p;
import 'package:secure_archive/secure_archive.dart';
import 'package:secure_archive_app/src/utils/ui.dart';
import 'package:secure_archive_app/src/utils/validators.dart';
import 'package:window_manager/window_manager.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  if (Platform.isWindows || Platform.isLinux || Platform.isMacOS) {
    await windowManager.ensureInitialized();
    await windowManager.setSize(const Size(900, 600));
  }

  runApp(const MainApp());
}

class MainApp extends StatelessWidget {
  const MainApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(home: PageContent());
  }
}

enum TabPages { backup, restore }

class _BackupPage extends HookWidget {
  const _BackupPage();

  @override
  Widget build(BuildContext context) {
    final formKey = useMemoized(() => GlobalKey<FormState>());
    useAutomaticKeepAlive();

    final inputDirectoryController = useTextEditingController();
    final outputFileController = useTextEditingController();
    final passwordTextController = useTextEditingController();
    final passwordController = useMemoized(() => FancyPasswordController());

    final integrityVerification = useState(true);
    final skipPasswordConfirmation = useState(false);

    final backupFuture = useState<Future<void>?>(null);
    final backupState = useFuture(backupFuture.value);

    final disableInteraction =
        backupState.connectionState == ConnectionState.waiting;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8),
      child: Form(
        key: formKey,
        child: ListView(
          children: [
            TextFormField(
              controller: inputDirectoryController,
              enabled: !disableInteraction,
              decoration: InputDecoration(
                labelText: 'Directory to Backup',
                floatingLabelBehavior: FloatingLabelBehavior.always,
                suffixIcon: IconButton(
                  onPressed: () async {
                    final selectedDirectory = await FilePicker.platform
                        .getDirectoryPath(
                          lockParentWindow: true,
                          dialogTitle: 'Directory to Backup',
                        );

                    if (selectedDirectory != null) {
                      inputDirectoryController.text = selectedDirectory;
                    }
                  },
                  icon: const Icon(MdiIcons.folderOpen),
                ),
              ),
              validator: (value) {
                return validatePath(value) ?? validateDirectoryExisting(value);
              },
            ),
            const SizedBox(height: 8),
            TextFormField(
              controller: outputFileController,
              enabled: !disableInteraction,
              decoration: InputDecoration(
                labelText: 'Backup File',
                floatingLabelBehavior: FloatingLabelBehavior.always,
                suffixIcon: IconButton(
                  onPressed: () async {
                    final timestamp = DateFormat(
                      'yyyy-MM-dd_HHmmss',
                    ).format(DateTime.now());

                    var basename = '';
                    if (validateDirectoryExisting(
                          inputDirectoryController.text,
                        ) ==
                        null) {
                      basename =
                          '_${p.basename(inputDirectoryController.text)}';
                    }

                    final outputFile = await FilePicker.platform.saveFile(
                      lockParentWindow: true,
                      dialogTitle: 'Backup File',
                      fileName: 'backup${basename}_$timestamp.sa',
                      type: FileType.custom,
                    );

                    if (outputFile != null) {
                      outputFileController.text = outputFile;
                    }
                  },
                  icon: const Icon(MdiIcons.archiveArrowDown),
                ),
              ),
              validator: (value) {
                final validation =
                    validatePath(value) ?? validateFileNotExisting(value);

                if (validation == null &&
                    validateDirectoryExisting(inputDirectoryController.text) ==
                        null) {
                  if (p.isWithin(inputDirectoryController.text, value!)) {
                    return 'Output file is within backup folder';
                  }
                }

                return validation;
              },
            ),
            const SizedBox(height: 8),
            FancyPasswordField(
              controller: passwordTextController,
              enabled: !disableInteraction,
              passwordController: passwordController,
              enableSuggestions: false,
              autocorrect: false,
              enableIMEPersonalizedLearning: false,
              keyboardType: TextInputType.visiblePassword,
              decoration: const InputDecoration(
                labelText: 'Password',
                floatingLabelBehavior: FloatingLabelBehavior.always,
              ),
              validationRules: {MinCharactersValidationRule(5)},
              validator: (value) {
                //Make sure since onChange is sometimes unreliable
                passwordController.onChange(value ?? '');

                return passwordController.areAllRulesValidated
                    ? null
                    : 'Not Validated';
              },
            ),
            const SizedBox(height: 16),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              value: integrityVerification.value,
              onChanged: disableInteraction
                  ? null
                  : (value) {
                      integrityVerification.value = value;
                    },
              title: const Text('Verify Backup Integrity'),
              subtitle: const Text(
                'Automatically check that backups are complete and restorable',
              ),
            ),
            ExpansionTile(
              enabled: !disableInteraction,
              childrenPadding: EdgeInsets.zero,
              tilePadding: EdgeInsets.zero,
              title: const Text('Advanced'),
              children: [
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  value: skipPasswordConfirmation.value,
                  onChanged: disableInteraction
                      ? null
                      : (value) {
                          skipPasswordConfirmation.value = value;
                        },
                  title: const Text('Skip Password Confirmation Prompt'),
                ),
              ],
            ),
            const SizedBox(height: 16),
            if (disableInteraction)
              const Column(
                children: [LinearProgressIndicator(), Text('Creating Backup')],
              )
            else
              FilledButton.icon(
                icon: const Icon(MdiIcons.safe),
                onPressed: () async {
                  if (formKey.currentState?.validate() ?? false) {
                    if (!skipPasswordConfirmation.value) {
                      final confirmation = await showDialog<String>(
                        context: context,
                        builder: (context) {
                          final controller = TextEditingController();

                          return AlertDialog(
                            title: const Text('Password Confirmation'),
                            content: TextField(
                              controller: controller,
                              enableSuggestions: false,
                              autocorrect: false,
                              enableIMEPersonalizedLearning: false,
                              keyboardType: TextInputType.visiblePassword,
                              obscureText: true,
                              decoration: const InputDecoration(
                                labelText: 'Password',
                                floatingLabelBehavior:
                                    FloatingLabelBehavior.always,
                              ),
                            ),
                            actions: [
                              TextButton(
                                onPressed: () {
                                  Navigator.of(context).pop();
                                },
                                child: const Text('Cancel'),
                              ),
                              TextButton(
                                onPressed: () {
                                  Navigator.of(context).pop(controller.text);
                                },
                                child: const Text('Confirm'),
                              ),
                            ],
                          );
                        },
                      );

                      if (confirmation != passwordTextController.text) {
                        if (context.mounted) {
                          showErrorMessage(context, 'Passwords do not match');
                        }

                        return;
                      }
                    }

                    final backup = SecureArchivePack(
                      outputFile: File(outputFileController.text),
                      sourceDirectory: Directory(inputDirectoryController.text),
                      argon2Params: Argon2Params.memoryConstrained(),
                    );
                    backupFuture.value = backup.pack(
                      passwordTextController.text,
                      integrityCheck: integrityVerification.value,
                    );
                  }
                },
                label: const Text('Backup'),
              ),
          ],
        ),
      ),
    );
  }
}

class _RestorePage extends HookWidget {
  const _RestorePage();

  @override
  Widget build(BuildContext context) {
    final formKey = useMemoized(() => GlobalKey<FormState>());
    useAutomaticKeepAlive();

    final outputDirectoryController = useTextEditingController();
    final inputFileController = useTextEditingController();
    final passwordTextController = useTextEditingController();

    final restoreFuture = useState<Future<void>?>(null);
    final restoreState = useFuture(restoreFuture.value);

    useEffect(() {
      if (restoreState.hasError) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          showErrorMessage(context, restoreState.error!.toString());
        });
      }

      return null;
    }, [restoreState.hasError, restoreState.error]);

    final disableInteraction =
        restoreState.connectionState == ConnectionState.waiting;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8),
      child: Form(
        key: formKey,
        child: ListView(
          children: [
            TextFormField(
              controller: inputFileController,
              enabled: !disableInteraction,
              decoration: InputDecoration(
                labelText: 'Backup File',
                floatingLabelBehavior: FloatingLabelBehavior.always,
                suffixIcon: IconButton(
                  onPressed: () async {
                    final outputFileResult = await FilePicker.platform
                        .pickFiles(
                          lockParentWindow: true,
                          dialogTitle: 'Backup File',
                          type: FileType.custom,
                          allowedExtensions: ['*'],
                        );

                    final pickedFilePath =
                        outputFileResult?.files.firstOrNull?.path;
                    if (pickedFilePath != null) {
                      inputFileController.text = pickedFilePath;
                    }
                  },
                  icon: const Icon(MdiIcons.archiveArrowUp),
                ),
              ),
              validator: (value) {
                final validation =
                    validatePath(value) ?? validateFileExisting(value);

                return validation;
              },
            ),
            const SizedBox(height: 8),
            TextFormField(
              controller: outputDirectoryController,
              enabled: !disableInteraction,
              decoration: InputDecoration(
                labelText: 'Directory to Restore',
                floatingLabelBehavior: FloatingLabelBehavior.always,
                suffixIcon: IconButton(
                  onPressed: () async {
                    final selectedDirectory = await FilePicker.platform
                        .getDirectoryPath(
                          lockParentWindow: true,
                          dialogTitle: 'Directory to Restore',
                        );

                    if (selectedDirectory != null) {
                      outputDirectoryController.text = selectedDirectory;
                    }
                  },
                  icon: const Icon(MdiIcons.folderOpen),
                ),
              ),
              validator: (value) {
                return validatePath(value) ??
                    validateDirectoryNotExisting(value);
              },
            ),
            const SizedBox(height: 8),
            TextFormField(
              controller: passwordTextController,
              enabled: !disableInteraction,
              enableSuggestions: false,
              autocorrect: false,
              enableIMEPersonalizedLearning: false,
              keyboardType: TextInputType.visiblePassword,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Password',
                floatingLabelBehavior: FloatingLabelBehavior.always,
              ),
              validator: (value) {
                return validateRequired(value, name: 'Password');
              },
            ),
            const SizedBox(height: 16),
            if (disableInteraction)
              const Column(
                children: [LinearProgressIndicator(), Text('Restoring Backup')],
              )
            else
              FilledButton.icon(
                icon: const Icon(MdiIcons.backupRestore),
                onPressed: () {
                  if (formKey.currentState?.validate() ?? false) {
                    final backup = SecureArchiveUnpack(
                      inputFile: File(inputFileController.text),
                      outputDirectory: Directory(
                        outputDirectoryController.text,
                      ),
                      argon2Params: Argon2Params.memoryConstrained(),
                    );
                    restoreFuture.value = backup.unpack(
                      passwordTextController.text,
                    );
                  }
                },
                label: const Text('Restore'),
              ),
          ],
        ),
      ),
    );
  }
}

class PageContent extends HookWidget {
  @override
  Widget build(BuildContext context) {
    final tabController = useTabController(initialLength: 2);
    final tabPage = useListenableSelector(
      tabController,
      () => TabPages.values[tabController.index],
    );

    return Scaffold(
      appBar: AppBar(
        title: switch (tabPage) {
          TabPages.backup => const Text('Create Backup'),
          TabPages.restore => const Text('Restore Backup'),
        },
        bottom: TabBar(
          controller: tabController,
          tabs: const [
            Tab(icon: Icon(MdiIcons.packageDown), text: 'Backup'),
            Tab(icon: Icon(MdiIcons.packageUp), text: 'Restore'),
          ],
        ),
      ),
      body: TabBarView(
        controller: tabController,
        children: const [_BackupPage(), _RestorePage()],
      ),
    );
  }
}
