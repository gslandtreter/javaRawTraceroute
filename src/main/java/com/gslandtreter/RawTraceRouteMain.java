package com.gslandtreter;

import java.net.InetAddress;

public class RawTraceRouteMain {
    public static void main(String[] args) {
        if(args.length < 1 || args.length > 2) {
            System.err.println("usage: Ping host [count]");
            System.exit(1);
        }

        try {
            final InetAddress address = InetAddress.getByName(args[0]);
            final int ttl;

            if(args.length == 2)
                ttl = Integer.parseInt(args[1]);
            else
                ttl = 30;

            final int id = 65535;
            final RawTraceRoute traceRoute = new RawTraceRoute(id, 1000);

            System.out.println("Tracing " + args[0] + ". Max hops: " + ttl);
            System.out.println(traceRoute.execute(address, ttl));

        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
