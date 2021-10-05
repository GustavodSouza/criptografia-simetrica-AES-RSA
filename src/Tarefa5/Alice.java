package Tarefa5;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;

public class Alice {
    public static void main(String[] args) {
        try {
            PublicKey chavePublicaBob;

            //Gera o par de chaves RSA
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            final KeyPair key = keyGen.generateKeyPair();

            //Inicializa a conexão com Bob
            Socket socket = new Socket("localhost", 5555);

            //Recebe o objeto de Bob.
            ObjectInputStream oin = new ObjectInputStream(socket.getInputStream());
            ObjetoTroca objetoRecebido = (ObjetoTroca) oin.readObject();

            //Armazena a chave de Bob.
            chavePublicaBob = objetoRecebido.getChavePublica();

            //Chave AES para criptografia.
            Cipher cipherAES = Cipher.getInstance("AES");
            SecretKey keyAES = KeyGenerator.getInstance("AES").generateKey();
            cipherAES.init(Cipher.ENCRYPT_MODE, keyAES);

            JFileChooser fc = new JFileChooser("");
            System.out.println("Selecionando arquivo");

            if (fc.showDialog(new JFrame(), "OK") == JFileChooser.APPROVE_OPTION) {
                File f = fc.getSelectedFile();
                FileInputStream fin = new FileInputStream(f);
                byte[] bArray = new byte[(int) fin.getChannel().size()];
                fin.read(bArray);
                System.out.println("[Alice] Arquivo selecionado");

                //Criptografa o arquivo com AES
                byte[] textoCifrado = cipherAES.doFinal(bArray);

                //Criptografar a chave AES com a chave Publica de Bob.
                Cipher cipherRSA = Cipher.getInstance("RSA");
                cipherRSA.init(Cipher.ENCRYPT_MODE, chavePublicaBob);
                byte[] chaveCifrada = cipherRSA.doFinal(keyAES.getEncoded());

                //Seta o ObjetoTroca com (Arquivo cripto, Chave AES cripto, Chave publica de Alice)
                ObjetoTroca objetoTroca = new ObjetoTroca();
                objetoTroca.setArquivo(textoCifrado);
                objetoTroca.setNomeArquivo(f.getName());
                objetoTroca.setChaveSessao(chaveCifrada);
                objetoTroca.setChavePublica(key.getPublic());

                //Converte o ObjetoTroca para Byte[]
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                new ObjectOutputStream(bOut).writeObject(objetoTroca);

                byte[] bArrayObjetoTroca = bOut.toByteArray();

                //Gerar o Hash/Resumo
                byte[] hash = MessageDigest.getInstance("SHA-256").digest(bArrayObjetoTroca);

                //Gera a assinatura
                cipherRSA.init(Cipher.ENCRYPT_MODE, key.getPrivate());
                byte[] assinatura = cipherRSA.doFinal(hash);

                //Seta a assinatura para dentro do ObjetoTroca.
                objetoTroca.setAssinatura(assinatura);

                ObjectOutputStream objetoSaida = new ObjectOutputStream(socket.getOutputStream());
                objetoSaida.writeObject(objetoTroca);

                socket.close();
            }

        } catch (Exception e) {
            System.out.println("O seguinte erro foi encontrado: " +e);
        }
    }
}
