/**
* ECE681 : RFC Algorithm Packet Classification
* By Amit Bhalera0, ECE Department, NJIT.
* Decription : Packet lookup/classification Program : RFC algorithm implementation
**/

import java.io.*;
import java.util.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.BitSet;
import java.lang.instrument.Instrumentation;


public class PacketLookup {
	static long avgtime = 0,totalpackets = 0;
	static int PerformanceFlag = 1;
	static int ConsoleDisplay = 1;
	static int MemoryCalculate = 1;
	static int debug = 0;
	
	public static void main(String[] args) {
		
		//PerformanceFlag = Integer.parseInt(args[2]); 
		//ConsoleDisplay = Integer.parseInt(args[3]);
		String FileName = args[0];
		String TestPacketsFile = args[1];
		Phase RFC_Phase0 = new Phase();
		Phase1 RFC_Phase1 = new Phase1();
		Phase2 RFC_Phase2 = new Phase2();
		if(ConsoleDisplay == 0)
		{
			try{
				PrintStream out = new PrintStream(new FileOutputStream("output.txt"));
				System.setOut(out);
					
			}catch(IOException e1){
				System.out.println("Error");
			}
		}
		/*RFC Preprocessing
		 * Creating all RFC tables and CBM tables*/
		long starttime = System.currentTimeMillis();
		RFCMapping(RFC_Phase0,RFC_Phase1,RFC_Phase2,FileName);
		long endtime = System.currentTimeMillis();
		if(PerformanceFlag == 1)
		{
			System.out.print(" Preprocessing time : "+((endtime-starttime))+"ms");
		}
		
		if(MemoryCalculate == 1)
		{
			long memsize = 0;
			int i;
			for(i=0;i<6;i++)
			{
				memsize += (RFC_Phase0.RFCTable[i].length * Integer.SIZE)/8;
				//System.out.println("\nLength of RFCphase0.rfctable[0] "+RFC_Phase0.RFCTable[i].length);
				
			}
			memsize += (RFC_Phase1.RFCTable[0].length * Integer.SIZE)/8;
			//System.out.println("\nLength of RFCphase0.rfctable[0] "+RFC_Phase1.RFCTable[0].length);
			
			memsize += (RFC_Phase1.RFCTable[1].length * Integer.SIZE)/8;
			//System.out.println("\nLength of RFCphase0.rfctable[0] "+RFC_Phase1.RFCTable[1].length);
			memsize += (RFC_Phase2.RFCTable.length * Integer.SIZE)/8;
			//System.out.println("\nLength of RFCphase0.rfctable[0] "+RFC_Phase2.RFCTable.length);
			System.out.print(" TotalMemsize in bytes : "+(float)(memsize/1000)+"MB");
		}
		int SA_IP0,SA_IP1, DA_IP0,DA_IP1, DA_port,Protocol,IPDecode,Phase1_eqid0,Phase1_eqid1,Phase0coef0,Phase0coef1,Phase0coef2,Phase0coef3,Phase1coef0;
		int eof =0,FinalPhase_eqid,MatchingRuleID;
		byte [] IP_SA,IP_DA;
		String[] Components;
		
		//Creating coefficients for mapping equation from number of entries present in CBM tables
		Phase0coef0 = RFC_Phase0.Eq_ID[1]*RFC_Phase0.Eq_ID[4];
		Phase0coef1 = RFC_Phase0.Eq_ID[4];
		Phase0coef2 = RFC_Phase0.Eq_ID[3]*RFC_Phase0.Eq_ID[5];
		Phase0coef3 = RFC_Phase0.Eq_ID[5];
		Phase1coef0 = RFC_Phase1.Eq_ID[1];
		try{
			BufferedReader buff = new BufferedReader(new FileReader(TestPacketsFile));
			String TestPacket = buff.readLine();
			InetAddress testip,InputSAIP,InputDAIP;
			byte [] IPtest;
			while(eof != 1 && TestPacket!=null){	
				Components = TestPacket.split("\t");
				try{
					
					InputSAIP = InetAddress.getByName(Components[0]);
					IP_SA = InputSAIP.getAddress();
					IPDecode = 0;
					IPDecode = (IPDecode+(IP_SA[0]& 0xFF))<<8;
					IPDecode = (IPDecode+(IP_SA[1]& 0xFF));
					SA_IP0 = IPDecode;
					
					IPDecode = 0;
					IPDecode = (IPDecode+(IP_SA[2]& 0xFF))<<8;
					IPDecode = (IPDecode+(IP_SA[3]& 0xFF));
					SA_IP1 = IPDecode;
					
					InputDAIP = InetAddress.getByName(Components[1]);
					
					IP_DA = InputDAIP.getAddress();
					IPDecode = 0;
					IPDecode = (IPDecode+(IP_DA[0]& 0xFF))<<8;
					IPDecode = (IPDecode+(IP_DA[1]& 0xFF));
					DA_IP0 = IPDecode;
					
					IPDecode = 0;
					IPDecode = (IPDecode+(IP_DA[2]& 0xFF))<<8;
					IPDecode = (IPDecode+(IP_DA[3]& 0xFF));
					DA_IP1 = IPDecode;
					
					DA_port = Integer.parseInt(Components[3]);
					Protocol = Integer.parseInt(Components[4]);
					
					if(PerformanceFlag == 0)
					{	
						System.out.print("\n"+InputSAIP+"\t");
						System.out.print(""+InputDAIP+"\t");
						System.out.print(+DA_port+"\t");
						System.out.print(""+Protocol+"\t");
					}
					//Giving input to RFC algorithm 
					long starttime1 = System.nanoTime();
					
					FinalPhase_eqid = (Phase1coef0 * RFC_Phase1.RFCTable[0][(Phase0coef0 * RFC_Phase0.RFCTable[0][SA_IP0]) + (Phase0coef1 * RFC_Phase0.RFCTable[1][SA_IP1]) +
					                  (RFC_Phase0.RFCTable[4][Protocol])]) + RFC_Phase1.RFCTable[1][(Phase0coef2 * RFC_Phase0.RFCTable[2][DA_IP0]) + 
					                  (Phase0coef3 * RFC_Phase0.RFCTable[3][DA_IP1]) +(RFC_Phase0.RFCTable[5][DA_port])];
					
					MatchingRuleID = RFC_Phase2.RFCTable[FinalPhase_eqid];
					
					long endtime1 = System.nanoTime();
					
					if(PerformanceFlag == 0)
					{
						System.out.print("Matching Rule : " +MatchingRuleID);
						if(MatchingRuleID == Integer.parseInt(Components[6]))
						{
							System.out.print(" RULE MATCHED\n");
						}
						else{
						
							System.out.println(" **RULE UNMATCHED** Expected Rule : "+Integer.parseInt(Components[6]));
						}
					}
					avgtime+=(endtime1-starttime1);
					totalpackets++;
					
					
				}catch (UnknownHostException e)
				{
					System.out.println("\nError : " +e.getMessage());
				}
				TestPacket = buff.readLine();
			}
		}catch(IOException e)
		{
			System.out.println("\n Error : "+e.toString());
		}
		
		if(PerformanceFlag == 1)
		{	
			System.out.println(" TotalTime : "+(avgtime)+"ns TotalPacckets :"+totalpackets+" Avg: "+((avgtime/totalpackets))+"ns");
		}
		
		
	}
	public static void RFCMapping(Phase RFC_Phase0,Phase1 RFC_Phase1,Phase2 RFC_Phase2, String FileName)
	{
		
		InetAddress IPaddress_SA,IPaddress_DA;
		int eof = 0,IPdec = 0,LineCount = 0,i,j,Input_Prefix;
		byte [] IP_SA,IP_DA;
		int IPSA0[],IPSA1[],IPDA0[],IPDA1[],PrefSA0[],PrefSA1[],PrefDA0[],PrefDA1[],L4portStart[],L4portEnd[];
		int RuleNo = 0;
		String [] L4DST_port;
		int Portstartid,Portendid;
		int ProtocolId,ProtocolPrefix;
		
		//Memory creation
		
		LinkedList<EqIpPrefix> TempEqIpPrefix_0 = new LinkedList<EqIpPrefix>();
		LinkedList<EqIpPrefix> TempEqIpPrefix_1 = new LinkedList<EqIpPrefix>();
		LinkedList<EqIpPrefix> TempEqIpPrefix_2 = new LinkedList<EqIpPrefix>();
		LinkedList<EqIpPrefix> TempEqIpPrefix_3 = new LinkedList<EqIpPrefix>();
		LinkedList<EqIpPrefix> TempEqIpPrefix_4 = new LinkedList<EqIpPrefix>();
		LinkedList<EqIpPrefix> TempEqIpPrefix_5 = new LinkedList<EqIpPrefix>();
		
		LinkedList<BitSet> TempCBM0 = new LinkedList<BitSet>();
		LinkedList<BitSet> TempCBM1 = new LinkedList<BitSet>();
		LinkedList<BitSet> TempCBM2 = new LinkedList<BitSet>();
		LinkedList<BitSet> TempCBM3 = new LinkedList<BitSet>();
		LinkedList<BitSet> TempCBM4 = new LinkedList<BitSet>();
		LinkedList<BitSet> TempCBM5 = new LinkedList<BitSet>();
		
		RFC_Phase0.RFCTable[0] = new int[65536];  //Chunk0 SA part_0
		RFC_Phase0.RFCTable[1] = new int[65536];  //Chunk1 SA part_1
		RFC_Phase0.RFCTable[2] = new int[65536];  //Chunk2 DA part_0
		RFC_Phase0.RFCTable[3] = new int[65536];  //Chunk3 DA part_1
		RFC_Phase0.RFCTable[4] = new int[256];  //Chunk4 L4_Protocol
		RFC_Phase0.RFCTable[5] = new int[65536];  //Chunk5 Dst_Port
		
		
		try{
			//Count no. of rules to create table of required size = rules
			LineNumberReader lnr = new LineNumberReader(new FileReader(FileName));
			lnr.skip(Long.MAX_VALUE);
			LineCount = lnr.getLineNumber()+1;			//Total lines or Rules in input file 
			System.out.print("\nTotalRules : " + LineCount);
			lnr.close();
			
			//storing IP SA and DA in temp memmory...it ll be used for CBM creation
			IPSA0 = new int[LineCount];
			IPSA1 = new int[LineCount];
			IPDA0 = new int[LineCount];
			IPDA1 = new int[LineCount];
			PrefSA0 = new int[LineCount];
			PrefSA1 = new int[LineCount];
			PrefDA0 = new int[LineCount];
			PrefDA1 = new int[LineCount];
			
			L4portStart = new int[LineCount];
			L4portEnd = new int[LineCount];
			
			
			BitSet Temp0 = new BitSet(LineCount);
			TempCBM0.add(0, Temp0);		
			BitSet Temp1 = new BitSet(LineCount);
			TempCBM1.add(0, Temp1);		
			BitSet Temp2 = new BitSet(LineCount);
			TempCBM2.add(0, Temp2);		
			BitSet Temp3 = new BitSet(LineCount);
			TempCBM3.add(0, Temp3);		
			BitSet Temp4 = new BitSet(LineCount);
			TempCBM4.add(0, Temp4);		
			BitSet Temp5 = new BitSet(LineCount);
			TempCBM5.add(0, Temp5);		
			
			
			BufferedReader buff = new BufferedReader(new FileReader(FileName));
			String line = buff.readLine();
			while(eof != 1 && line!=null){
				String[] Component = line.split("\t");
				if(debug == 1)
				{
					System.out.println("\nSA: "+Component[0]+" DA: "+Component[1]+" SPA: "+Component[2]+" DPA: "+Component[3]+" Pro: "+Component[4]+Component[5]);
				}
				try{
					
					//Source IP@ 1st Chunk
					String[] IPadd = Component[0].split("/", 2);
					IPaddress_SA = InetAddress.getByName(IPadd[0]);
					Input_Prefix = (Integer.parseInt(IPadd[1]))>16 ? 16:(Integer.parseInt(IPadd[1]));
					IP_SA = IPaddress_SA.getAddress();
					IPdec = 0;
					IPdec = (IPdec+(IP_SA[0]& 0xFF))<<8;
					IPdec = (IPdec+(IP_SA[1]& 0xFF));
					if(debug == 1)
					{
						System.out.print("\nChunk 0: "+IPdec+" Prefix: "+Input_Prefix);
					}
					IPSA0[RuleNo] = IPdec;
					PrefSA0[RuleNo] = Input_Prefix;
					RFC_Phase0.Eq_ID[0] = CreatePhase0_RFCTable(RFC_Phase0.Eq_ID[0],RFC_Phase0.RFCTable[0],IPdec,Input_Prefix,16,TempEqIpPrefix_0,
							LineCount,RuleNo ,TempCBM0 );
					
					//Source IP@ 2nd Chunk
					IPdec = 0;
					IPdec = (IPdec+(IP_SA[2]& 0xFF))<<8;
					IPdec += (IP_SA[3]& 0xFF);
					Input_Prefix = (Integer.parseInt(IPadd[1])-16)>0 ? (Integer.parseInt(IPadd[1])-16):0;
					if(debug == 1)
					{
						System.out.println("\tChunk 1: "+IPdec+ " Prefix : "+Input_Prefix);
					}
					IPSA1[RuleNo] = IPdec;
					PrefSA1[RuleNo] = Input_Prefix;
					RFC_Phase0.Eq_ID[1] = CreatePhase0_RFCTable(RFC_Phase0.Eq_ID[1],RFC_Phase0.RFCTable[1],IPdec,Input_Prefix,16,TempEqIpPrefix_1,
							LineCount,RuleNo ,TempCBM1 );
					
					//Destination IP@ 1st Chunk
					IPadd = Component[1].split("/", 2);
					IPaddress_DA = InetAddress.getByName(IPadd[0]);
					IP_DA = IPaddress_DA.getAddress();
					Input_Prefix = (Integer.parseInt(IPadd[1]))>16 ? 16:(Integer.parseInt(IPadd[1]));
					IPdec = 0;
					IPdec = (IPdec+(IP_DA[0]& 0xFF))<<8;
					IPdec = (IPdec+(IP_DA[1]& 0xFF));
					if(debug == 1)
					{
						System.out.print("\nChunk 2: "+IPdec+" Prefix: "+Input_Prefix);
					}
					IPDA0[RuleNo] = IPdec;
					PrefDA0[RuleNo] = Input_Prefix;
					RFC_Phase0.Eq_ID[2] = CreatePhase0_RFCTable(RFC_Phase0.Eq_ID[2],RFC_Phase0.RFCTable[2],IPdec,Input_Prefix,16,TempEqIpPrefix_2,
							LineCount,RuleNo ,TempCBM2 );
					
					//Destination IP@ 2nd chunk
					IPdec = 0;
					IPdec = (IPdec+(IP_DA[2]& 0xFF))<<8;
					IPdec += (IP_DA[3]& 0xFF);
					Input_Prefix = (Integer.parseInt(IPadd[1])-16)>0 ? (Integer.parseInt(IPadd[1])-16):0;
					if(debug == 1)
					{
						System.out.println("\tChunk 3: "+IPdec+ " Prefix : "+Input_Prefix);
					}
					IPDA1[RuleNo] = IPdec;
					PrefDA1[RuleNo] = Input_Prefix;
					RFC_Phase0.Eq_ID[3] = CreatePhase0_RFCTable(RFC_Phase0.Eq_ID[3],RFC_Phase0.RFCTable[3],IPdec,Input_Prefix,16,TempEqIpPrefix_3,
							LineCount,RuleNo ,TempCBM3 );
					
					//Protocol field
					IPadd = Component[4].split("/", 2);
					ProtocolId = Integer.decode(IPadd[0]);
					ProtocolPrefix = Integer.decode(IPadd[1]);
					ProtocolPrefix = ProtocolPrefix > 0 ? 8 : 0;
					RFC_Phase0.Eq_ID[4] = CreatePhase0_RFCTable(RFC_Phase0.Eq_ID[4],RFC_Phase0.RFCTable[4],ProtocolId,ProtocolPrefix,8,TempEqIpPrefix_4,
							LineCount,RuleNo ,TempCBM4 );
					
					//L4 Destination port
					L4DST_port = Component[3].split(" : ", 2);
					Portstartid = Integer.parseInt(L4DST_port[0]);
					Portendid = Integer.parseInt(L4DST_port[1]);
					L4portStart[RuleNo] = Portstartid;
					L4portEnd[RuleNo] = Portendid;
					RFC_Phase0.Eq_ID[5] = CreateRFCTable_L4Port(RFC_Phase0.Eq_ID[5],RFC_Phase0.RFCTable[5],Portstartid,Portendid,TempEqIpPrefix_5,
							LineCount,RuleNo ,TempCBM5 );
					
					//
					RuleNo++;
					}catch (UnknownHostException e)
					{
						System.out.println("\nError : " +e.getMessage());
					}
				line = buff.readLine();
			}
			for(j=0;j<6;j++)
			{
				RFC_Phase0.Eq_ID[j]++;
				RFC_Phase0.CBMTable[j] = new BitSet[RFC_Phase0.Eq_ID[j]];
				for(i=0;i<RFC_Phase0.Eq_ID[j];i++)
					RFC_Phase0.CBMTable[j][i] = new BitSet(LineCount);
				
			}	
			
			CreatePhase0_CBMTable(RFC_Phase0.CBMTable[0],RFC_Phase0.Eq_ID[0],TempCBM0);
			if(PerformanceFlag == 0)
			{
				System.out.println("\nChunk 0 :");
				for(i=0;i<RFC_Phase0.Eq_ID[0];i++)
				{
					System.out.print("\nChunk0_EqId "+i+"\t");
					for(j=LineCount-1; j>=0; j--)
				      System.out.print(RFC_Phase0.CBMTable[0][i].get(j)? 1 : 0);
				}
			}
			
			CreatePhase0_CBMTable(RFC_Phase0.CBMTable[1],RFC_Phase0.Eq_ID[1],TempCBM1);
			if(PerformanceFlag == 0)
			{
				System.out.println("\nChunk 1 :");
				for(i=0;i<RFC_Phase0.Eq_ID[1];i++)
				{
					System.out.print("\nChunk1_EqId "+i+"\t");
					for(j=LineCount-1; j>=0; j--)
				      System.out.print(RFC_Phase0.CBMTable[1][i].get(j)? 1 : 0);
				}
			}
			
			CreatePhase0_CBMTable(RFC_Phase0.CBMTable[2],RFC_Phase0.Eq_ID[2],TempCBM2);
			if(PerformanceFlag == 0)
			{
				System.out.println("\nChunk 2 :");
				for(i=0;i<RFC_Phase0.Eq_ID[2];i++)
				{
					System.out.print("\nChunk2_EqId "+i+"\t");
					for(j=LineCount-1; j>=0; j--)
				      System.out.print(RFC_Phase0.CBMTable[2][i].get(j)? 1 : 0);
				}
			}
			
			CreatePhase0_CBMTable(RFC_Phase0.CBMTable[3],RFC_Phase0.Eq_ID[3],TempCBM3);
			if(PerformanceFlag == 0)
			{
				System.out.println("\nChunk 3 :");
				for(i=0;i<RFC_Phase0.Eq_ID[3];i++)
				{
					System.out.print("\nChunk3_EqId "+i+"\t");
					for(j=LineCount-1; j>=0; j--)
				      System.out.print(RFC_Phase0.CBMTable[3][i].get(j)? 1 : 0);
				}
			}
			CreatePhase0_CBMTable(RFC_Phase0.CBMTable[4],RFC_Phase0.Eq_ID[4],TempCBM4);
			
			if(PerformanceFlag == 0)
			{
				System.out.println("\nChunk 4 :");
				for(i=0;i<RFC_Phase0.Eq_ID[4];i++)
				{
					System.out.print("\nChunk4_EqId "+i+"\t");
					for(j=LineCount-1; j>=0; j--)
				      System.out.print(RFC_Phase0.CBMTable[4][i].get(j)? 1 : 0);
				}
			}
			
			CreatePhase0_CBMTable(RFC_Phase0.CBMTable[5],RFC_Phase0.Eq_ID[5],TempCBM5);
			if(PerformanceFlag == 0)
			{
				System.out.println("\nChunk 5 :");
				for(i=0;i<RFC_Phase0.Eq_ID[5];i++)
				{
					System.out.print("\nChunk5_EqId "+i+"\t");
					for(j=LineCount-1; j>=0; j--)
				      System.out.print(RFC_Phase0.CBMTable[5][i].get(j)? 1 : 0);
				}
			}	
			//RFC tables for Phase 1
			CreatePhase1_RFC_CBM_Table(RFC_Phase0, RFC_Phase1,LineCount);
			
			//RFC tables for phase 2
			CreatePhase2_RFC_CBM_Table(RFC_Phase1, RFC_Phase2,LineCount);
			
		}catch(IOException e)
		{
			System.out.println("\n Error : "+e.toString());
		}
		
	}
	public static int CreatePhase0_RFCTable(int Eq_Id,int [] RFCTable, int Input_IP, int Input_Prefix,int ChunkBits,
			LinkedList<EqIpPrefix> TempEqIpPrefix,int RuleCount,int RuleNo ,LinkedList<BitSet> CBM )
	{
		
		int j,entrys;
		if(Input_Prefix != 0){
				
			if(RFCTable[Input_IP] == 0)
			{
				RFCTable[Input_IP] = ++Eq_Id;
				EqIpPrefix StoreThis = new EqIpPrefix();
				StoreThis.ipaddress = Input_IP;
				StoreThis.prefixe = Input_Prefix;
				TempEqIpPrefix.add(StoreThis);
				BitSet Temp = new BitSet();
				Temp = new BitSet(RuleCount);
				Temp.set(RuleCount - RuleNo - 1);
				CBM.add(Eq_Id, Temp);
				
				//for remanining entrys if any
				entrys = (int) java.lang.Math.pow(2,(ChunkBits - Input_Prefix));
				for(j=entrys;j>1;j--)
				{
					if(RFCTable[Input_IP + j - 1] == 0)
						RFCTable[Input_IP + j - 1] = Eq_Id;
					else
					{
						CBM.get(RFCTable[Input_IP + j - 1]).or(CBM.get(Eq_Id));
					}
				}
			}
			else
			{
				/*for more specific IP address entry in RFC table. Subset of IP@ should not be given same eq_id as that of
				its superset */
				if((TempEqIpPrefix.get(RFCTable[Input_IP]-1).ipaddress != Input_IP) &&
					(TempEqIpPrefix.get(RFCTable[Input_IP]-1).prefixe != Input_Prefix))
				{
					BitSet Temp = new BitSet();
					Temp = new BitSet(RuleCount);
					Temp.set(RuleCount - RuleNo - 1);
					Temp.or(CBM.get(RFCTable[Input_IP]));
					RFCTable[Input_IP] = ++Eq_Id; //storing at updated eq_id
					CBM.add(Eq_Id, Temp);
					
					EqIpPrefix StoreThis = new EqIpPrefix();
					StoreThis.ipaddress = Input_IP;
					StoreThis.prefixe = Input_Prefix;
					TempEqIpPrefix.add(StoreThis);
					
					//For remaining entrys in RFCtable
					entrys = (int) java.lang.Math.pow(2,(ChunkBits - Input_Prefix));
					for(j=entrys;j>1;j--)
					{
						if(RFCTable[Input_IP + j - 1] == 0)
							RFCTable[Input_IP + j - 1] = Eq_Id;
						else
						{
							CBM.get(RFCTable[Input_IP + j - 1]).or(CBM.get(Eq_Id));
						}		
					}
				}
				else
					CBM.get(RFCTable[Input_IP]).set(RuleCount - RuleNo - 1);
				
			}
		}
		else{
			CBM.get(0).set(RuleCount - RuleNo - 1);
		}
		return Eq_Id;
	}
	
	public static int CreateRFCTable_L4Port(int Eq_Id,int [] RFCTable, int start, int end,LinkedList<EqIpPrefix> TempEqIpPrefix,
			int RuleCount,int RuleNo ,LinkedList<BitSet> CBM)
	{
		int j;
		if(start != 0 & end != 65535){
				
			if(RFCTable[start] == 0)
			{
				RFCTable[start] = ++Eq_Id;
				EqIpPrefix StoreThis = new EqIpPrefix();
				StoreThis.ipaddress = start;
				StoreThis.prefixe = end;
				TempEqIpPrefix.add(StoreThis);
				
				BitSet Temp = new BitSet();
				Temp = new BitSet(RuleCount);
				Temp.set(RuleCount - RuleNo - 1);
				CBM.add(Eq_Id, Temp);
			
				//for remanining entrys if any
				for(j=start+1;j<=end;j++)
				{
					if(RFCTable[j] == 0)
						RFCTable[j] = Eq_Id;
					else
						CBM.get(RFCTable[j]).or(CBM.get(Eq_Id));
				}
			}
			else
			{
				/*for more specific IP address entry in RFC table. Subset of IP@ should not be given same eq_id as that of
				its superset */
				if((TempEqIpPrefix.get(RFCTable[start]-1).ipaddress != start) &&
					(TempEqIpPrefix.get(RFCTable[start]-1).prefixe != end))
				{
					BitSet Temp = new BitSet();
					Temp = new BitSet(RuleCount);
					Temp.set(RuleCount - RuleNo - 1);
					Temp.or(CBM.get(RFCTable[start]));
					RFCTable[start] = ++Eq_Id; //storing at updated eq_id
					CBM.add(Eq_Id, Temp);
					EqIpPrefix StoreThis = new EqIpPrefix();
					StoreThis.ipaddress = start;
					StoreThis.prefixe = end;
					TempEqIpPrefix.add(StoreThis);
	
					for(j=start+1;j<=end;j++)
					{
						if(RFCTable[j] == 0)
							RFCTable[j] = Eq_Id;
						else
							CBM.get(RFCTable[j]).or(CBM.get(Eq_Id));
					}
				}
				else
				{
					CBM.get(RFCTable[start]).set(RuleCount - RuleNo - 1);
				}	
			}
		}
		else
		{
			CBM.get(0).set(RuleCount - RuleNo - 1);
		}
		return Eq_Id;
	}
	
	public static void CreatePhase0_CBMTable(BitSet [] CBMTable,int Eq_Id,LinkedList<BitSet> CBMList){
		
		int i;
		//Updating all CBM bitmaps with wildcard entry bitmap... here it will always be first entry in CBM table.
		for(i=0;i<Eq_Id;i++)
		{	
			CBMList.get(i).or(CBMList.get(0));
			CBMTable[i].or(CBMList.get(i));;
		}
	}
	
	public static void CreatePhase1_RFC_CBM_Table(Phase RFCPhase0, Phase1 RFCPhase1,int RuleCount)
	{
		int Eq_Id,i,j,k,CBMno,C1[] = {0,1,4,2,3,5};
		Map<String, Integer> HashMap = new HashMap<String, Integer>();
		int RFCTable0size,x,y,z;
		//
		for(CBMno = 0;CBMno < 2;CBMno++)
		{	
			
			RFCTable0size = (RFCPhase0.Eq_ID[C1[CBMno*3+0]])*(RFCPhase0.Eq_ID[C1[CBMno*3+1]])*(RFCPhase0.Eq_ID[C1[CBMno*3+2]]);
			x = (RFCPhase0.Eq_ID[C1[CBMno*3+1]])*(RFCPhase0.Eq_ID[C1[CBMno*3+2]]);
			y = (RFCPhase0.Eq_ID[C1[CBMno*3+2]]);
			z = 0;
			Eq_Id = 0;
			HashMap.clear();
			RFCPhase1.RFCTable[CBMno]=new int[RFCTable0size];
			RFCPhase1.CBMTable[CBMno] = new BitSet[RFCTable0size];
			BitSet Temp0 = new BitSet(RuleCount);
			BitSet Temp1 = new BitSet(RuleCount);
			BitSet Temp2 = new BitSet(RuleCount);
			BitSet Temp = new BitSet(RuleCount);
			
			for(i=0;i<RFCPhase0.Eq_ID[C1[CBMno*3+0]];i++)
			{	
				Temp0 = RFCPhase0.CBMTable[C1[CBMno*3+0]][i];
				for(j=0;j<RFCPhase0.Eq_ID[C1[CBMno*3+1]];j++)
				{
					Temp1 = RFCPhase0.CBMTable[C1[CBMno*3+1]][j];
					for(k=0;k<RFCPhase0.Eq_ID[C1[CBMno*3+2]];k++)
					{
						Temp2 = RFCPhase0.CBMTable[C1[CBMno*3+2]][k];
						Temp.or(Temp0);
						Temp.and(Temp1);
						Temp.and(Temp2);
						z = i*x + y*j + k; 
						if(HashMap.get(Temp.toString()) == null)
						{
							RFCPhase1.CBMTable[CBMno][Eq_Id] = new BitSet(RuleCount);
							RFCPhase1.CBMTable[CBMno][Eq_Id].or(Temp);
							HashMap.put(Temp.toString(), Eq_Id);
							RFCPhase1.RFCTable[CBMno][z]= Eq_Id; 
							Eq_Id++;
						}
						else
						{
							RFCPhase1.RFCTable[CBMno][z]= HashMap.get(Temp.toString());
						}
						Temp.clear();
					}
				}	
			}
			RFCPhase1.Eq_ID[CBMno] = Eq_Id;
			if(PerformanceFlag == 0)
			{
				System.out.print("\n\nRFCPhase1 CBM \n");
				for(i=0;i<Eq_Id;i++)
				{
					System.out.print("\nChunk"+CBMno+"_EqId "+i+"\t");
					for(j=RuleCount-1; j>=0; j--)
				      System.out.print(RFCPhase1.CBMTable[CBMno][i].get(j)? 1 : 0);
				}
			}	
			
		}
	}
	
	public static void CreatePhase2_RFC_CBM_Table(Phase1 RFCPhase1, Phase2 RFCPhase2,int RuleCount)
	{
		int i,j;
			
		int RFCTable0size = (RFCPhase1.Eq_ID[0])*(RFCPhase1.Eq_ID[1]);
		int y = (RFCPhase1.Eq_ID[1]);
		int z = 0;
		RFCPhase2.RFCTable =new int[RFCTable0size];
		BitSet Temp0 = new BitSet(RuleCount);
		BitSet Temp1 = new BitSet(RuleCount);
		BitSet Temp = new BitSet(RuleCount);
		
		for(i=0;i<RFCPhase1.Eq_ID[0];i++)
		{	
			Temp0 = RFCPhase1.CBMTable[0][i];
			for(j=0;j<RFCPhase1.Eq_ID[1];j++)
			{
				Temp1 = RFCPhase1.CBMTable[1][j];
				
					Temp.or(Temp0);
					Temp.and(Temp1);
					z = y*i + j; 
					
					RFCPhase2.RFCTable[z]= RuleCount - Temp.length(); 
					
					Temp.clear();
			}	
		}
		
		if(PerformanceFlag == 0)
		{
			System.out.print("\nFinal RFCTable Phase 2 : \n");
			for(i=0;i<RFCTable0size;i++)
			{
				  System.out.print("\n ID"+i+" : "+RFCPhase2.RFCTable[i]);
			}
		}
	}
	
}
class EqIpPrefix 
{
	int ipaddress;
	int prefixe;
};
class Phase
{
	int [][] RFCTable = new int[6][];
	BitSet [][] CBMTable = new BitSet[6][];
	int Eq_ID[] = new int[6];
};
class Phase1
{
	int [][] RFCTable = new int[2][];
	BitSet [][] CBMTable = new BitSet[2][];
	int Eq_ID[] = new int[2];
}
class Phase2
{
	int RFCTable[];
}
