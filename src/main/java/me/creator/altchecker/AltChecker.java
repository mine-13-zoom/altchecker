package com.creator.altchecker;
import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;

import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.command.SimpleCommand.Invocation;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import org.yaml.snakeyaml.Yaml;

@Plugin(id = "altchecker", name = "AltChecker", version = "1.0-SNAPSHOT",
        url = "https://github.com/YourUsername/AltChecker", description = "Checks for alt accounts", authors = {"Creator"})
public class AltChecker {

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataFolder;

    private String dbHost;
    private int dbPort;
    private String dbName;
    private String dbUser;
    private String dbPassword;
    private Connection conn;

    @Inject
    public AltChecker(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataFolder = dataDirectory;
        loadConfig();
        initDatabase();
        registerCommand();
    }

    private void loadConfig() {
        if (!Files.exists(dataFolder)) {
            try {
                Files.createDirectories(dataFolder);
            } catch (IOException e) {
                logger.error("Failed to create data folder", e);
            }
        }

        File configFile = new File(dataFolder.toFile(), "config.yml");
        if (!configFile.exists()) {
            try (InputStream in = getClass().getClassLoader().getResourceAsStream("config.yml")) {
                Files.copy(in, configFile.toPath());
            } catch (IOException e) {
                logger.error("Failed to copy config.yml", e);
            }
        }

        try {
            Yaml yaml = new Yaml();
            Map<String, Object> config = yaml.load(Files.newInputStream(configFile.toPath()));
            Map<String, Object> databaseConfig = (Map<String, Object>) config.get("database");
            dbHost = (String) databaseConfig.get("host");
            dbPort = (int) databaseConfig.get("port");
            dbName = (String) databaseConfig.get("name");
            dbUser = (String) databaseConfig.get("username");
            dbPassword = (String) databaseConfig.get("password");
        } catch (IOException e) {
            logger.error("Failed to load config.yml", e);
        }
    }

    private void initDatabase() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            String url = "jdbc:mysql://" + dbHost + ":" + dbPort + "/" + dbName + "?useSSL=false&autoReconnect=true";
            conn = DriverManager.getConnection(url, dbUser, dbPassword);

            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE IF NOT EXISTS ip_links (" +
                        "account VARCHAR(32) NOT NULL, " +
                        "ip VARCHAR(45) NOT NULL, " +
                        "UNIQUE(account, ip))");
            }
        } catch (SQLException | ClassNotFoundException e) {
            logger.error("Failed to initialize database", e);
        }
    }

    @Subscribe
    public void onJoin(PostLoginEvent e) {
        Player p = e.getPlayer();
        String name = p.getUsername();
        String ip = p.getRemoteAddress().getAddress().getHostAddress();

        try {
            PreparedStatement ps = conn.prepareStatement("INSERT IGNORE INTO ip_links (account, ip) VALUES (?, ?)");
            ps.setString(1, name);
            ps.setString(2, ip);
            ps.executeUpdate();
            ps.close();

            // find other accounts on this ip
            PreparedStatement ps2 = conn.prepareStatement("SELECT account FROM ip_links WHERE ip = ?");
            ps2.setString(1, ip);
            ResultSet rs = ps2.executeQuery();
            List<String> alts = new ArrayList<>();
            while (rs.next()) {
                String acc = rs.getString("account");
                if (!acc.equalsIgnoreCase(name)) {
                    alts.add(acc);
                }
            }
            rs.close();
            ps2.close();

            if (!alts.isEmpty()) {
                String msg = "§c[AltChecker] " + name + " is using the same IP as: " + String.join(", ", alts);
                server.getAllPlayers().stream()
                        .filter(pl -> pl.hasPermission("altchecker.notify"))
                        .forEach(staff -> staff.sendMessage(Component.text(msg)));
            }

        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    private void registerCommand() {
        server.getCommandManager().register("alts", new SimpleCommand() {
            @Override
            public void execute(Invocation invocation) {
                if (!invocation.source().hasPermission("altchecker.alts")) {
                    invocation.source().sendMessage(Component.text("§cNo permission."));
                    return;
                }

                String[] args = invocation.arguments();
                if (args.length != 1) {
                    invocation.source().sendMessage(Component.text("§cUsage: /alts <username|ip>"));
                    return;
                }

                String query = args[0];
                Set<String> accounts = new HashSet<>();
                Set<String> ips = new HashSet<>();

                try {
                    // BFS to find cluster
                    Queue<String> accQueue = new ArrayDeque<>();
                    Queue<String> ipQueue = new ArrayDeque<>();

                    if (query.contains(".")) {
                        ipQueue.add(query);
                    } else {
                        accQueue.add(query);
                    }

                    while (!accQueue.isEmpty() || !ipQueue.isEmpty()) {
                        while (!accQueue.isEmpty()) {
                            String acc = accQueue.poll();
                            if (accounts.add(acc)) {
                                PreparedStatement ps = conn.prepareStatement("SELECT ip FROM ip_links WHERE account=?");
                                ps.setString(1, acc);
                                ResultSet rs = ps.executeQuery();
                                while (rs.next()) {
                                    String foundIp = rs.getString("ip");
                                    if (!ips.contains(foundIp)) ipQueue.add(foundIp);
                                }
                                rs.close();
                                ps.close();
                            }
                        }
                        while (!ipQueue.isEmpty()) {
                            String ip = ipQueue.poll();
                            if (ips.add(ip)) {
                                PreparedStatement ps = conn.prepareStatement("SELECT account FROM ip_links WHERE ip=?");
                                ps.setString(1, ip);
                                ResultSet rs = ps.executeQuery();
                                while (rs.next()) {
                                    String foundAcc = rs.getString("account");
                                    if (!accounts.contains(foundAcc)) accQueue.add(foundAcc);
                                }
                                rs.close();
                                ps.close();
                            }
                        }
                    }

                } catch (SQLException e) {
                    e.printStackTrace();
                }

                invocation.source().sendMessage(Component.text("§eLinked accounts: §f" + String.join(", ", accounts)));
                invocation.source().sendMessage(Component.text("§eIPs: §f" + String.join(", ", ips)));
            }
        });
    }
}

