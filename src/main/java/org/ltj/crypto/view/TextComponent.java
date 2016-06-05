/*
 * Copyright (c) 1995, 2008, Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle or the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */ 

package org.ltj.crypto.view;
/*
 * TextComponent.java requires one additional file:
 *   DocumentSizeFilter.java
 */

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ltj.cryptoeditor.crypto.encryption.*;

import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.security.Security;
import java.util.HashMap;

import javax.swing.*;
import javax.swing.text.*;
import javax.swing.event.*;
import javax.swing.undo.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class TextComponent extends JFrame {
    private JTextPane textPane;
    private AbstractDocument doc;
    private JTextArea outputText;
    private String newline = "\n";
    private HashMap<Object, Action> actions;

    private Encryption encryption;
    private EncryptionMode mode;
    private EncryptionType type;
    private EncryptionOptions options;
    private JMenu optionsMenu, modeMenu;

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

    //undo helpers
    protected UndoAction undoAction;
    protected RedoAction redoAction;
    protected UndoManager undo = new UndoManager();


    //The standard main method.
    public static void main(String[] args) {
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

        Security.addProvider(new BouncyCastleProvider());

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
        scrollPane.setPreferredSize(new Dimension(600, 400));

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
        JMenu editMenu = createEditMenu();
        JMenuBar mb = new JMenuBar();
        mb.add(editMenu);
        mb.add(createTypeMenu());

        modeMenu = initModes();
        optionsMenu = initOptions();

        mb.add(modeMenu);
        mb.add(optionsMenu);
        mb.add(createEncryptButton());
        mb.add(createDecryptButton());
        mb.add(new JSeparator(JSeparator.VERTICAL));
        mb.add(createSwapButton());
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
        for (EncryptionMode m : type.getSupportedModes()){
            JRadioButtonMenuItem item = new JRadioButtonMenuItem(m.toString());
            group.add(item);
            modeMenu.add(item);
            item.addActionListener(ae -> {
                setMode(EncryptionMode.valueOf(m.toString()));
            });
        }
        if (group.getElements().hasMoreElements()){
            group.getElements().nextElement().setSelected(true);
            mode = type.getSupportedModes()[0];
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
            for (EncryptionOptions o : mode.getSupportedPaddings()) {
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

    private JButton createEncryptButton(){
        JButton button = new JButton("Encrypt");
        button.addActionListener(ae -> {
            BCCryptographer cryptographer = BCCryptographer.getInstance();
            try {
                SecretKey key = getCurrentKey();
                String encrypted = cryptographer.encrypt(textPane.getText(), encryption, key);
                outputText.setText(encrypted);
            } catch (Exception e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(this, e.getMessage());
            }
        });

        return button;
    }

    private SecretKey getCurrentKey(){
        if (type == EncryptionType.DES)
            return desKey;
        else
            return aesKey;

    }

    private JButton createDecryptButton(){
        JButton button = new JButton("Decrypt");
        button.addActionListener(ae -> {
            BCCryptographer cryptographer = BCCryptographer.getInstance();
            try {
                SecretKey key = getCurrentKey();
                String decrypted = cryptographer.decrypt(textPane.getText(), encryption, key);
                outputText.setText(decrypted);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });

        return button;
    }

    private JButton createSwapButton(){
        JButton button = new JButton("Swap Values");
        button.addActionListener(ae -> {
            textPane.setText(outputText.getText());
            outputText.setText("");
        });

        return button;
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

