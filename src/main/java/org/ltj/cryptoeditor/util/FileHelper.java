package org.ltj.cryptoeditor.util;


import java.io.*;

public class FileHelper {


    public static void writeToPath(String source, String path){
        PrintStream out = null;
        FileOutputStream fileOut = null;
        try {
            fileOut = new FileOutputStream(path);
            out = new PrintStream(fileOut);
            out.print(source);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } finally {
            if (out != null){
                out.close();
            }
            if (fileOut != null){
                try {fileOut.close();} catch (IOException e) {}
            }
        }
    }

    public static String readFromPath(String path){
        BufferedReader buffReader = null;
        StringBuilder body = new StringBuilder();
        try {
            InputStream in = new FileInputStream(path);
            InputStreamReader inReader = new InputStreamReader(in);
            buffReader = new BufferedReader(inReader);

            String nextLine;

            while ((nextLine = buffReader.readLine()) != null){
                body.append(nextLine);
                body.append('\n');
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {

            try {
                if (buffReader != null){
                    buffReader.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }

        return body.toString();
    }

}
