"use strict";

class Captcha {
    constructor() {
        this.name ='captcha';
        
        this.definition = {
            guid: {
                type: "text",
                size: 254,
                unique: true,
                required: true
            },
            answer: {
                type: "text",
                size: 254,
                unique: false,
                required: true
            },
            expiration_date: {
                type: "date",
                time: true,
                required: true
            },
            is_used: {
                type: "boolean",
                defaultValue: false,
                required: true
            }
        };
        
        this.helpers=null;
        this.hasOne=null;
        this.hasMany=null;
        this.extendsTo=null;
        this.defaultData=null;
    }
}

module.exports = () => new Captcha();

