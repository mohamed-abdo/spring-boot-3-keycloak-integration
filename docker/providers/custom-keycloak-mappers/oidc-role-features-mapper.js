var roles = [];
user.getRoleMappings().forEach(function(roleModel){
        var attr = {};
        var roleName = roleModel.getName();
        var map = roleModel.getAttributes();
        map.forEach(function(key, value){
            attr[key] = value;
        });
        roles[roleName] = attr;
});
exports = roles;