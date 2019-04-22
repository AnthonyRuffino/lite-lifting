class File {
    constructor() {
        this.name = 'file';
                
        this.definition = {
            name: {
                type: "text",
                size: 254,
                required: true
            },
            content_type: {
                type: "text",
                size: 254,
                required: true
            },
            content: {
                type: "binary",
                required: false
            },
            last_modified: {
                type: "date",
                time: true,
                required: true
            }
        };
        
        this.hasOne = [];
        this.hasOne.push({
            name: 'user',
            options: {
                required: true
            }
        });
        
        this.uniqueConstraints = [];
        this.uniqueConstraints.push({columns: ['user_id','name']});
        
        this.helpers = null;
        this.hasMany = null;
        this.extendsTo = null;
        this.defaultData = null;
    }
}

module.exports = () => new File();
