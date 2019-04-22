"use strict";

class Role {
    constructor() {
        this.name = 'role';
        
        this.definition = {
            name: {
                type: "text",
                size: 60,
                unique: true
            },
        };
        
        this.helpers = {
            methods: {
        
            },
            validations: {
                
            }
        };
        
        this.hasOne = null;
        this.hasMany = null;
        this.extendsTo = null;
        
        
        //////////////////////
        //DEFAULT DATA////////
        //////////////////////
        this.defaultData = [];
        this.defaultData.push({values: {
            id: 1,
            name: 'admin'
        }});
        this.defaultData.push({values: {
            id: 2,
            name: 'moderator'
        }});
        this.defaultData.push({values: {
            id: 3,
            name: 'user'
        }});
        this.defaultData.push({values: {
            id: 4,
            name: 'client'
        }});
    }
}

module.exports = () => new Role();
