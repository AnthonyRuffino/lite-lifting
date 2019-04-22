"use strict";

class Token {
    constructor() {
        this.name = 'token';
        
        this.definition = {
            val: {
                type: "text",
                size: 254,
                unique: true,
                required: true
            },
            expriration_date: {
                type: "date",
                time: true,
                required: true
            },
            type: {
                type: "enum",
                values: ["Signup", "Session"],
                required: true
            },
            client: {
                type: "enum",
                values: ["Browser", "App", "Other"],
                required: true
            }
        };
        
        this.helpers = {
            methods: {
        
            },
            validations: {
                
            }
        };
        
        this.hasOne = [];
        this.hasOne.push({
            name: 'user',
            options: {
                required: false,
                reverse: 'tokens'
            }
        });
        
        this.hasMany = [];
        this.hasMany.push({
        
        });
        
        this.extendsTo = [];
        this.extendsTo.push({
        
        });
        
        this.hasMany = null;
        this.extendsTo = null;
        this.defaultData = null;
        
        
        //////////////////////
        //DEFAULT DATA////////
        //////////////////////
        this.defaultData = [];
        
        
    
    }
}

module.exports = () => new Token();
