/*
 * lib-flex-esign
 *
 * Copyright (C) 2010
 * Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * 
 * Desarrollo apoyado por la Superintendencia de Servicios de Certificación 
 * Electrónica (SUSCERTE) durante 2010-2014 por:
 * Ing. Felix D. Lopez M. - flex.developments@gmail.com | flopez@suscerte.gob.ve
 * Ing. Yessica De Ascencao - yessicadeascencao@gmail.com | ydeascencao@suscerte.gob.ve
 *
 * Este programa es software libre; Usted puede usarlo bajo los terminos de la
 * licencia de software GPL version 2.0 de la Free Software Foundation.
 *
 * Este programa se distribuye con la esperanza de que sea util, pero SIN
 * NINGUNA GARANTIA; tampoco las implicitas garantias de MERCANTILIDAD o
 * ADECUACION A UN PROPOSITO PARTICULAR.
 * Consulte la licencia GPL para mas detalles. Usted debe recibir una copia
 * de la GPL junto con este programa; si no, escriba a la Free Software
 * Foundation Inc. 51 Franklin Street,5 Piso, Boston, MA 02110-1301, USA.
 */

package flex.eSign.operators.signers.components;

/**
 * ImageSignPreferences
 * 
 * @author Ing. Felix D. Lopez M. - flex.developments@gmail.com
 * @author Ing. Yessica De Ascencao - yessicadeascencao@gmail.com
 * @version 1.0
 */
public final class ImageSignPreferences {
    private String name = null;
    private String type = null;
    private String imageVisible = null;
    private String path = null;
    private String posX = null;
    private String posY = null;
    private String height = null;
    private String width = null;
    private String page = null;
    private String reason = null;
    private String locate = null;
    
    public ImageSignPreferences () {}
    
    public ImageSignPreferences(
        String name,
        String type,
        String imageVisible,
        String path,
        String posX,
        String posY,
        String height,
        String width,
        String page,
        String reason,
        String locate
    ) {
        
        setName(name);
        setType(type);
        setImageVisible(imageVisible);
        setPath(path);
        setPosX(posX);
        setPosY(posY);
        setHeight(height);
        setWidth(width);
        setPage(page);
        setReason(reason);
        setLocate(locate);
    }
    
    public String getName() {
        return name;
    }

    public void setName(String name) {
        if(ifAccept(name)) this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        if(ifAccept(type)) this.type = type;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        if(ifAccept(path)) this.path = path;
    }

    public String getImageVisible() {
        return imageVisible;
    }

    public void setImageVisible(String imageViisble) {
        if(ifAccept(imageViisble)) this.imageVisible = imageViisble;
    }

    public String getPosX() {
        return posX;
    }

    public void setPosX(String posX) {
        if(ifAccept(posX)) this.posX = posX;
    }

    public String getPosY() {
        return posY;
    }

    public void setPosY(String posY) {
        if(ifAccept(posY)) this.posY = posY;
    }

    public String getHeight() {
        return height;
    }

    public void setHeight(String heigth) {
        if(ifAccept(heigth)) this.height = heigth;
    }

    public String getWidth() {
        return width;
    }

    public void setWidth(String width) {
        if(ifAccept(width)) this.width = width;
    }

    public String getPage() {
        return page;
    }

    public void setPage(String page) {
        if(ifAccept(page)) this.page = page;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        if(ifAccept(reason)) this.reason = reason;
    }

    public String getLocate() {
        return locate;
    }

    public void setLocate(String locate) {
        if(ifAccept(locate)) this.locate = locate;
    }
    
    private boolean ifAccept(String value) {
        if(value == null) return false;
        if( (value.isEmpty() || (value.toUpperCase().compareTo("NULL") == 0) ) ) return false;
        else return true;
    }
}
