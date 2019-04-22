"use strict";
const now = () => new Date().toJSON().slice(0, 19).replace('T', ' ');
class User {
    constructor() {
        this.name = 'user';
        
        this.definition = {
            username: {
                type: "text",
                size: 254,
                unique: true,
                required: true
            },
            email: {
                type: "text",
                size: 254,
                required: false
            },
            password: {
                type: "text",
                size: 254,
                required: true
            },
            is_locked: {
                type: "boolean",
                defaultValue: false,
                required: true
            },
            is_confirmed: {
                type: "boolean",
                defaultValue: false,
                required: true
            },
            login_attempts_since_last_success: {
                type: "integer",
                size: 2,
                defaultValue: 0,
                required: true
            },
            last_login_time: {
                type: "date",
                time: true
            },
            status: {
                type: "enum",
                values: ["Client", "User", "Rep", "Admin"],
                required: true
            },
            signup_time: {
                type: "date",
                time: true,
                required: true
            },
            lock_date: {
                type: "date",
                time: true,
                required: false
            }
        };
        
        
        /////////////////////
        //ENTITY HELPERS/////
        /////////////////////
        this.helpers = {
            methods: {
                //userNameAndEmail: function() {
                //    return this.username + ' (' + this.email + ')';
                //}
            },
            validations: {
                //age: orm.enforce.ranges.number(0, undefined, "under-age")
            }
        };
        
        this.hasOne = null;
        /*
        this.hasOne = [];
        this.hasOne.push({
            name: 'role',
            options: {
                required: false,
                reverse: 'users',
                autoFetch : true
            }
        });
        */
        
        this.hasMany = [];
        this.hasMany.push({
            name: 'role',
            desc: 'role',
            options: {
                reverse: 'users',
                key: true,
                accessor: 'Roles'
            },
            meta: {
                why: String,
                num: {
                    type: 'integer',
                    size: 2,
                    defaultValue: 0
                }
            }
        });
        
        //this.uniqueConstraints = [];
        //this.uniqueConstraints.push({columns: ['role_id','user_id']});
        
        
        ////////////////////////////
        //EXTENDS TO  ASSOCIATIONS//
        ////////////////////////////
        this.extendsTo = [];
        this.extendsTo.push({
            name: 'verification',
            data: {
                street: String,
                number: Number
            }
        });
        
        
        //////////////////////
        //DEFAULT DATA////////
        //////////////////////
        this.defaultData = [];
        ((defaultData) => {
            const bcrypt = require('bcrypt-nodejs');
            defaultData.push({
                values:{
                    id: 1,
                    username: 'admin',
                    password: bcrypt.hashSync('admin', bcrypt.genSaltSync(8), null),
                    is_locked: false,
                    is_confirmed: true,
                    login_attempts_since_last_success: 0,
                    last_login_time: now(),
                    status: 'Admin',
                    signup_time: now(),
                    lock_date: null
                },
                hasMany: {
                    role: [
                        {
                            id: 1,
                            meta: {
                                why: 'I made this',
                                num: 1
                            }
                        },
                        {
                            id: 2,
                            meta: {
                                why: 'I earned this',
                                num: 2
                            }
                        }
                    ]
                }
            });
            defaultData.push({
                values:{
                    id: 2,
                    username: 'rep',
                    password: bcrypt.hashSync('rep', bcrypt.genSaltSync(8), null),
                    is_locked: false,
                    is_confirmed: true,
                    login_attempts_since_last_success: 0,
                    last_login_time: now(),
                    status: 'Rep',
                    signup_time: now(),
                    lock_date: null
                },
                hasMany: {
                    role: [
                        {
                            id: 2,
                            meta: {
                                why: 'Admin likes me',
                                num: 3
                            }
                        }
                    ]
                }
            });
            defaultData.push({
                values:{
                    id: 3,
                    username: 'user',
                    password: bcrypt.hashSync('user', bcrypt.genSaltSync(8), null),
                    is_locked: false,
                    is_confirmed: true,
                    login_attempts_since_last_success: 0,
                    last_login_time: now(),
                    status: 'User',
                    signup_time: now(),
                    lock_date: null
                },
                hasMany: {
                    role: [
                        {
                            id: 3,
                            meta: {
                                why: 'I singed up',
                                num: 66
                            }
                        }
                    ]
                }
            });
            defaultData.push({
                values:{
                    id: 4,
                    username: 'client',
                    password: bcrypt.hashSync('client', bcrypt.genSaltSync(8), null),
                    is_locked: false,
                    is_confirmed: true,
                    login_attempts_since_last_success: 0,
                    last_login_time: now(),
                    status: 'Client',
                    signup_time: now(),
                    lock_date: null
                },
                hasMany: {
                    role: [
                        {
                            id: 4,
                            meta: {
                                why: 'I paid with bit coin',
                                num: 999
                            }
                        }
                    ]
                }
            });
        })(this.defaultData);
    }
}

module.exports = () => new User();