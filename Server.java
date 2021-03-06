
import java.io.*;
import java.net.*;
import java.util.*;
//--------------------------------------------------------------//
//程式流程
//---MyServer  --主類別檔
//-1-main  --主程式進入點
//-2-go()   --方法  --建位連線  --等待請求連線
//     --取得連線後往下執行
//-3-Process  --內部類別 --處理程序
//-3.1-Process  --建構子 --由執行緒呼叫 --建立接收
//-3.2-run()  --方法  --執行執行緒
//-3.3-tellApiece() --方法  --告訴每人
//--------------------------------------------------------------//
//MyServer主類別檔
//--------------------------------------------------------------//
public class Server{
 
 Vector output;//output
 //--------------------------------------------------------------//
 //-1-主程式進入點
 //--------------------------------------------------------------//
 public static void main (String args[]){
  new Server().go();     
 }
 //--------------------------------------------------------------//
 //-2-建位連線
 //--------------------------------------------------------------//
 public void go() {
  //建立物件陣列
 
	 
	 output = new Vector();          
 
  
  try{
   //產生ServerSocket設定port:5000
   ServerSocket serverSock = new ServerSocket(8888);  
   while(true){
    
    Socket cSocket = serverSock.accept();   //Listens for a connection to be made to this socket and accepts it. 
    //建立I/O管道
    PrintStream writer =  new PrintStream(cSocket.getOutputStream());  //Creates a new print stream.
     //取得Socket的輸出資料流
  
    
    //元件加入Vector
    output.add(writer);         
   
    //傳入一個Runnable物件並分派一個新的執行緒
    //建立伺服器主執行緒
    Thread t = new Thread(new Process(cSocket));  //Allocates a new Thread object.
    //啟動執行緒
    t.start();           
    //取得連線的ip       
    System.out.println(cSocket.getLocalSocketAddress()+ 
    //執行緒的在線次數
         "目前有"+(t.activeCount()-1)+"個連接");               
   } 
  }catch(Exception ex){System.out.println("連接失敗");}
 }
 
 
 
 
 
 //--------------------------------------------------------------//
 //-3-Process處理程序
 //--------------------------------------------------------------//
 public class Process implements Runnable{   
  //暫存資料的Buffered
  BufferedReader reader;  
  //建立一個Socket變數  
  Socket sock;            
  //----------------------------------------------------------//
  //-3.1-由執行緒呼叫---建立接收
  //----------------------------------------------------------//
  
  public Process(Socket cSocket)
  {
   try{
    sock = cSocket;
    //取得Socket的輸入資料流
    InputStreamReader isReader = new InputStreamReader(sock.getInputStream());  //Creates an InputStreamReader that uses the default charset.
        
    reader = new BufferedReader(isReader);
   }catch(Exception ex){
    System.out.println("連接失敗Process");
   } 
  }
 
  //--------------------------------------------------------------//
  //-3.2-執行執行緒
  //--------------------------------------------------------------//
  public void run(){
   String message;
   try{
       //讀取資料
    while ((message = reader.readLine())!=null){   
     System.out.println("收到"+message);
     tellApiece(message);
    }
   }catch(Exception ex){System.out.println("有一個連接離開");}
  }
  //--------------------------------------------------------------//
  //-3.3-告訴每人
  //--------------------------------------------------------------//
  public void tellApiece(String message){
   //產生iterator可以存取集合內的元素資料    
   Iterator it = output.iterator(); 
   //向下讀取元件   
   while(it.hasNext()){          
    try{
    //取集合內資料
    PrintStream writer = (PrintStream) it.next();  
    //印出
    writer.println(message); 
    //刷新該串流的緩衝。
    writer.flush();           
    }
    catch(Exception ex){
     System.out.println("連接失敗Process");
    }
   }
  }
 } 
}

