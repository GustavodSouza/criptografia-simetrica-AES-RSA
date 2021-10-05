package Tarefa5;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Arrays;

public class Bob {
    public static void main(String[] args) {
        try {
            byte[] assinaturaDecifrada;

            //Gera o par de chaves RSA
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            final KeyPair key = keyGen.generateKeyPair();

            //Recebe e aceita a conexão de Alice.
            ServerSocket ss = new ServerSocket(5555);
            System.out.println("[Bob] Aguardando conexão...");
            Socket s = ss.accept();

            //Bob envia sua chave publica.
            ObjetoTroca objetoTroca = new ObjetoTroca();
            objetoTroca.setChavePublica(key.getPublic());
            ObjectOutputStream out = new ObjectOutputStream(s.getOutputStream());
            out.writeObject(objetoTroca);

            ObjectInputStream oin = new ObjectInputStream(s.getInputStream());
            ObjetoTroca objetoRecebido = (ObjetoTroca) oin.readObject();

            //Descriptografa a assinatura com a chave publica de Alice;
            Cipher cipherRSA = Cipher.getInstance("RSA");
            cipherRSA.init(Cipher.DECRYPT_MODE, objetoRecebido.getChavePublica());

            //Descriptografa e armazena a assinatura;
            assinaturaDecifrada = cipherRSA.doFinal(objetoRecebido.getAssinatura());

            //"Retirado a assinatura do Objeto"
            objetoRecebido.setAssinatura(null);

            //Converte o objeto recebido para Byte[]
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            new ObjectOutputStream(bOut).writeObject(objetoRecebido);

            byte[] bArrayObjetoTroca = bOut.toByteArray();

            //Gerar o Hash/Resumo
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(bArrayObjetoTroca);

            //Comparação do Hash de Bob com a assinatura descriptografada.
            if (Arrays.equals(hash, assinaturaDecifrada)) {

                //Descriptografa a chave de Sessão com a chave privada de Bob
                cipherRSA.init(Cipher.DECRYPT_MODE, key.getPrivate());
                byte[] chaveSessaoCifrada = cipherRSA.doFinal(objetoRecebido.getChaveSessao());

                //Transforma a chave novamente para SecretKey
                SecretKey chaveAES = new SecretKeySpec(chaveSessaoCifrada, 0, chaveSessaoCifrada.length, "AES");

                Cipher cipherAES = Cipher.getInstance("AES");
                cipherAES.init(Cipher.DECRYPT_MODE, chaveAES);

                //Descriptografa o conteúdo do arquivo com a chave AES.
                byte[] textoPlano = cipherAES.doFinal(objetoRecebido.getArquivo());

                //Mostra o conteúdo do arquivo.
                System.out.println("[BOB] Texto plano decifrado: \n" + new String(textoPlano));

            } else {
                System.out.println("Conteúdo modificado!!!");
            }

        } catch (Exception e) {
            System.out.println("O seguinte erro foi encontrado: " +e);
        }
    }
}
