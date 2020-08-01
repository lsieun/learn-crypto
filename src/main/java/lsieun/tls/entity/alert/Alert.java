package lsieun.tls.entity.alert;

import lsieun.utils.ByteDashboard;

public class Alert {
    public final AlertLevel level;
    public final AlertDescription description;

    public Alert(AlertLevel level, AlertDescription description) {
        this.level = level;
        this.description = description;
    }

    public static Alert parse(byte[] bytes) {
        ByteDashboard bd = new ByteDashboard(bytes);

        byte b0 = bd.next();
        byte b1 = bd.next();

        AlertLevel level = AlertLevel.valueOf(b0);
        AlertDescription description = AlertDescription.valueOf(b1);

        return new Alert(level, description);
    }
}
