
package org.ltj.cryptoeditor.view;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ltj.cryptoeditor.crypto.encryption.*;
import org.ltj.cryptoeditor.util.FileHelper;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.*;
import javax.swing.event.*;
import javax.swing.undo.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.ltj.cryptoeditor.util.FileHelper.readFromPath;

public class TextComponent extends JFrame {
    private JTextPane textPane;
    private AbstractDocument doc;
    private JTextArea outputText;
    private HashMap<Object, Action> actions;

    private Encryption encryption;
    private EncryptionMode mode;
    private EncryptionType type;
    private EncryptionOptions options;
    private JMenu optionsMenu, modeMenu;
    private String password = "";
    private JCheckBox pbeBox, hashBox;

    private final static SecretKey aesKey = new SecretKeySpec(new byte[]{
            45, 9, 89, 93,
            39, -5, 2, 38,
            52, -111, -91, -118,
            0, 121, 110, 35
    }, "AES");
    private final static SecretKey desKey = new SecretKeySpec(new byte[]{
            45, 9, 89, 93,
            39, -5, 2, 38
    }, "DES");

    private final RSAPublicKey publicKey = BCCryptographer.getInstance().generatePublicKey("d46f473a2d746537de2056ae3092c451");
    private final RSAPrivateKey privateKey = BCCryptographer.getInstance().generatePrivateKey("d46f473a2d746537de2056ae3092c451","57791d5430d593164082036ad8b29fb1");

    //undo helpers
    protected UndoAction undoAction;
    protected RedoAction redoAction;
    protected UndoManager undo = new UndoManager();


    //The standard main method.
    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());
        //Schedule a job for the event dispatch thread:
        //creating and showing this application's GUI.
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                //Turn off metal's use of bold fonts
                UIManager.put("swing.boldMetal", Boolean.FALSE);
                createAndShowGUI();
            }
        });
    }

    private static void createAndShowGUI() {



        //Create and set up the window.
        final TextComponent frame = new TextComponent();
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        //Display the window.
        frame.pack();

        frame.setVisible(true);
    }

    public TextComponent() {
        super("Entwicklung Sicherer Systeme");

        //Create the text pane and configure it.
        textPane = new JTextPane();
        textPane.setCaretPosition(0);
        textPane.setMargin(new Insets(5,5,5,5));
        StyledDocument styledDoc = textPane.getStyledDocument();
        if (styledDoc instanceof AbstractDocument) {
            doc = (AbstractDocument)styledDoc;
        } else {
            System.err.println("Text pane's document isn't an AbstractDocument!");
            System.exit(-1);
        }
        JScrollPane scrollPane = new JScrollPane(textPane);
        scrollPane.setPreferredSize(new Dimension(800, 480));

        //Create the text area for the status log and configure it.
        outputText = new JTextArea(5, 30);
        outputText.setEditable(false);
        JScrollPane scrollPaneForLog = new JScrollPane(outputText);

        //Create a split pane for the change log and the text area.
        JSplitPane splitPane = new JSplitPane(
                                       JSplitPane.VERTICAL_SPLIT,
                                       scrollPane, scrollPaneForLog);
        splitPane.setOneTouchExpandable(true);


        //Add the components.
        getContentPane().add(splitPane, BorderLayout.CENTER);

        //Set up the menu bar.
        actions=createActionTable(textPane);
        JMenu fileMenu = createFileMenu();
        JMenu editMenu = createEditMenu();
        JMenuBar mb = new JMenuBar();
        mb.add(fileMenu);
        mb.add(editMenu);
        mb.add(createTypeMenu());

        modeMenu = initModes();
        optionsMenu = initOptions();

        mb.add(modeMenu);
        mb.add(optionsMenu);


        pbeBox = new JCheckBox("PBE");
        pbeBox.addActionListener(ae -> {
            if (pbeBox.isSelected()){
                promptPassword();
            }
        });
        mb.add(pbeBox);

        hashBox = new JCheckBox("Hash");

        mb.add(hashBox);

        mb.add(new JSeparator(JSeparator.VERTICAL));
        setJMenuBar(mb);

        options = EncryptionOptions.NoPadding;
        mode = EncryptionMode.ECB;
        type = EncryptionType.AES;
        encryption = new Encryption(type,mode,options);


        //Put the initial text into the text pane.
        initDocument();
        textPane.setCaretPosition(0);

        //Start watching for undoable edits and caret changes.
        doc.addUndoableEditListener(new MyUndoableEditListener());
        doc.addDocumentListener(new MyDocumentListener());



    }

    private void promptPassword(){
        password = JOptionPane.showInputDialog(this, "Choose a password.");
    }

    private JMenu createFileMenu(){
        JMenu file = new JMenu("File");

        JMenuItem loadFile = new JMenuItem("Load");
        loadFile.addActionListener(ae -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileFilter(new FileNameExtensionFilter("JSON", "json"));
            int result = chooser.showOpenDialog(this);


            if (result == JFileChooser.APPROVE_OPTION){
                String path = chooser.getSelectedFile().getPath();
                loadFromJson(path);
            }
        });

        JMenuItem saveFile = new JMenuItem("Save");
        saveFile.addActionListener(ae -> {
            String name = JOptionPane.showInputDialog(this, "Choose a name for your File.");

            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Choose Directory");
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            chooser.setAcceptAllFileFilterUsed(false);
            int state = chooser.showOpenDialog(this);

            if (state == JFileChooser.APPROVE_OPTION){
                try {
                    EncryptedPackage packet;
                    BCCryptographer cryptographer = BCCryptographer.getInstance();
                    if (hashBox.isSelected()){
                        HashPayload payload;
                        if (pbeBox.isSelected()){
                            payload = cryptographer.encryptWithHash(textPane.getText(), password, encryption);
                        } else {
                            payload = cryptographer.encryptWithHash(textPane.getText(), encryption,getCurrentKey());

                        }
                        packet = new EncryptedPackage(encryption,payload.cipherText,pbeBox.isSelected(),payload);
                    } else {
                        packet = new EncryptedPackage(encryption,encrypt(cryptographer),pbeBox.isSelected(),null);
                    }
                    FileHelper.writeToPath(packet.toJson(), chooser.getSelectedFile().getPath() + File.separatorChar + name + ".json");
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(this, e.getMessage());
                }
            }
        });

        file.add(loadFile);
        file.add(saveFile);

        return file;
    }

    private void loadFromJson(String path){
        try {
            String json = FileHelper.readFromPath(path);
            EncryptedPackage packet = EncryptedPackage.fromJson(json);
            BCCryptographer cryptographer = BCCryptographer.getInstance();
            outputText.setText("");
            setType(packet.encryption.type);
            setMode(packet.encryption.mode);
            setOptions(packet.encryption.options);
            encryption = packet.encryption;
            pbeBox.setSelected(packet.needsPassword);

            boolean hashingEnabled = packet.checkSum != null;
            hashBox.setSelected(hashingEnabled);

            if (packet.needsPassword){
                promptPassword();

                if (hashingEnabled){
                    HashDecryptionResult decrypted = cryptographer.decryptWithHash(packet.checkSum,password,encryption);
                    if (decrypted.temperedWith){
                        JOptionPane.showMessageDialog(this, "Your Message has been tampered with! Please advise with your Security Team!");
                    } else {
                        textPane.setText(decrypted.plainText);
                    }
                } else {
                    textPane.setText(packet.payload);
                    textPane.setText(decrypt(cryptographer));
                }
            } else {
                if (hashingEnabled){
                    HashDecryptionResult decrypted = cryptographer.decryptWithHash(packet.checkSum,encryption,getCurrentKey());
                    if (decrypted.temperedWith){
                        JOptionPane.showMessageDialog(this, "Your Message has been tampered with! Please advise with your Security Team!");
                    } else {
                        textPane.setText(decrypted.plainText);
                    }
                } else {
                    textPane.setText(packet.payload);
                    textPane.setText(decrypt(cryptographer));
                }
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, e.getMessage());
        }
    }

    private JMenu createTypeMenu(){
        JMenu menu = new JMenu("Encryption Type");


        ButtonGroup group = new ButtonGroup();
        for (EncryptionType t : EncryptionType.values()){
            JRadioButtonMenuItem item = new JRadioButtonMenuItem(t.toString());
            group.add(item);
            menu.add(item);
            item.addActionListener(ae -> {
                setType(EncryptionType.valueOf(t.toString()));
            });
        }

        group.getElements().nextElement().setSelected(true);


        return menu;
    }

    private void setType(EncryptionType encryptionType){
        type = encryptionType;
        encryption = new Encryption(type);
        resetModes();
    }

    private void resetModes(){
        modeMenu.removeAll();
        ButtonGroup group = new ButtonGroup();
        for (EncryptionMode m : type.supportedModes){
            JRadioButtonMenuItem item = new JRadioButtonMenuItem(m.toString());
            group.add(item);
            modeMenu.add(item);
            item.addActionListener(ae -> {
                setMode(EncryptionMode.valueOf(m.toString()));
            });
        }
        if (group.getElements().hasMoreElements()){
            group.getElements().nextElement().setSelected(true);
            mode = type.supportedModes[0];
        } else {
            mode = null;
        }

        resetOptions();
    }

    private JMenu initModes(){
        JMenu menu = new JMenu("Encryption Mode");

        ButtonGroup group = new ButtonGroup();

        for (EncryptionMode m : EncryptionMode.values()){
            JRadioButtonMenuItem item = new JRadioButtonMenuItem(m.toString());
            group.add(item);
            menu.add(item);
            item.addActionListener(ae -> {
                setMode(EncryptionMode.valueOf(m.toString()));
            });
        }

        group.getElements().nextElement().setSelected(true);

        return menu;
    }

    private void setMode(EncryptionMode encryptionMode){
        mode = encryptionMode;
        encryption = new Encryption(type,mode);
        resetOptions();
    }

    private void resetOptions(){

        optionsMenu.removeAll();

        if (mode != null) {
            ButtonGroup group = new ButtonGroup();
            for (EncryptionOptions o : mode.supportedPaddings) {
                JRadioButtonMenuItem item = new JRadioButtonMenuItem(o.toString());
                group.add(item);
                optionsMenu.add(item);
                item.addActionListener(ae -> {
                    setOptions(EncryptionOptions.valueOf(o.toString()));
                });
            }
            group.getElements().nextElement().setSelected(true);
        }
    }

    private JMenu initOptions(){
        JMenu menu = new JMenu("Encryption Options");

        ButtonGroup group = new ButtonGroup();

        for (EncryptionOptions m : EncryptionOptions.values()){
            JRadioButtonMenuItem item = new JRadioButtonMenuItem(m.toString());
            group.add(item);
            menu.add(item);
            item.addActionListener(ae -> {
                setOptions(EncryptionOptions.valueOf(m.toString()));
            });
        }

        group.getElements().nextElement().setSelected(true);

        return menu;
    }

    private void setOptions(EncryptionOptions encryptionOptions){
        options = encryptionOptions;
        encryption = new Encryption(type,mode,options);
    }



    private String encrypt(BCCryptographer cryptographer) throws Exception{
        if (type == EncryptionType.RSA){
            return cryptographer.encryptRsa(textPane.getText(),publicKey);
        }

        if (pbeBox.isSelected()){
            return cryptographer.encrypt(textPane.getText(),password, encryption);
        } else {
            return cryptographer.encrypt(textPane.getText(), encryption, getCurrentKey());
        }
    }

    private SecretKey getCurrentKey(){
        if (type == EncryptionType.DES)
            return desKey;
        else
            return aesKey;

    }



    private String decrypt(BCCryptographer cryptographer) throws Exception{
        if (type == EncryptionType.RSA){
            return cryptographer.decryptRsa(textPane.getText(),privateKey);
        }

        if (pbeBox.isSelected()){
            return cryptographer.decrypt(textPane.getText(),password, encryption);
        } else {
            return cryptographer.decrypt(textPane.getText(), encryption, getCurrentKey());
        }
    }



    //This one listens for edits that can be undone.
    protected class MyUndoableEditListener
                    implements UndoableEditListener {
        public void undoableEditHappened(UndoableEditEvent e) {
            //Remember the edit and update the menus.
            undo.addEdit(e.getEdit());
            undoAction.updateUndoState();
            redoAction.updateRedoState();
        }
    }

    //And this one listens for any changes to the document.
    protected class MyDocumentListener
                    implements DocumentListener {
        public void insertUpdate(DocumentEvent e) {
            displayEditInfo(e);
        }
        public void removeUpdate(DocumentEvent e) {
            displayEditInfo(e);
        }
        public void changedUpdate(DocumentEvent e) {
            displayEditInfo(e);
        }
        private void displayEditInfo(DocumentEvent e) {
            Document document = e.getDocument();
            int changeLength = e.getLength();
        }
    }

    //Create the edit menu.
    protected JMenu createEditMenu() {
        JMenu menu = new JMenu("Edit");

        //Undo and redo are actions of our own creation.
        undoAction = new UndoAction();
        menu.add(undoAction);

        redoAction = new RedoAction();
        menu.add(redoAction);

        menu.addSeparator();

        //These actions come from the default editor kit.
        //Get the ones we want and stick them in the menu.
        menu.add(getActionByName(DefaultEditorKit.cutAction));
        menu.add(getActionByName(DefaultEditorKit.copyAction));
        menu.add(getActionByName(DefaultEditorKit.pasteAction));



        menu.addSeparator();

        menu.add(getActionByName(DefaultEditorKit.selectAllAction));
        return menu;
    }

    protected void initDocument() {
        String initString[] = { "" };
    }


    //The following two methods allow us to find an
    //action provided by the editor kit by its name.
    private HashMap<Object, Action> createActionTable(JTextComponent textComponent) {
        HashMap<Object, Action> actions = new HashMap<Object, Action>();
        Action[] actionsArray = textComponent.getActions();
        for (int i = 0; i < actionsArray.length; i++) {
            Action a = actionsArray[i];
            actions.put(a.getValue(Action.NAME), a);
        }
	return actions;
    }

    private Action getActionByName(String name) {
        return actions.get(name);
    }

    class UndoAction extends AbstractAction {
        public UndoAction() {
            super("Undo");
            setEnabled(false);
        }

        public void actionPerformed(ActionEvent e) {
            try {
                undo.undo();
            } catch (CannotUndoException ex) {
                System.out.println("Unable to undo: " + ex);
                ex.printStackTrace();
            }
            updateUndoState();
            redoAction.updateRedoState();
        }

        protected void updateUndoState() {
            if (undo.canUndo()) {
                setEnabled(true);
                putValue(Action.NAME, undo.getUndoPresentationName());
            } else {
                setEnabled(false);
                putValue(Action.NAME, "Undo");
            }
        }
    }

    class RedoAction extends AbstractAction {
        public RedoAction() {
            super("Redo");
            setEnabled(false);
        }

        public void actionPerformed(ActionEvent e) {
            try {
                undo.redo();
            } catch (CannotRedoException ex) {
                System.out.println("Unable to redo: " + ex);
                ex.printStackTrace();
            }
            updateRedoState();
            undoAction.updateUndoState();
        }

        protected void updateRedoState() {
            if (undo.canRedo()) {
                setEnabled(true);
                putValue(Action.NAME, undo.getRedoPresentationName());
            } else {
                setEnabled(false);
                putValue(Action.NAME, "Redo");
            }
        }
    }


}

