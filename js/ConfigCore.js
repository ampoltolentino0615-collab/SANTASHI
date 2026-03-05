var ConfigCore = (function () {
  var instance,
    currentSelectItems = [],
    NOT_SELECTED_ID_STR = "_I",
    loaders = [];
  function load(nextFile) {
    var df = $.Deferred();
    return (
      loaders.push(
        $.ajax({
          type: "GET",
          url: nextFile,
          dataType: "json",
          dataFilter: function (data, type) {
            return (data = (data = (function (text) {
              return ("" + text)
                .split("<")
                .join("&lt;")
                .split(">")
                .join("&gt;")
                .split("&")
                .join("&amp;")
                .split("'")
                .join("&#39;");
            })(data))
              .split("\\n")
              .join("<br>"));
          },
          success: function (data) {
            for (var key in data);
            switch (key) {
              case "GRADE":
                instance.grade_list = data[key];
                break;
              case "ITEMS":
                instance.item_list = data[key];
                break;
              case "MATERIALS":
                instance.materials_list = data[key];
                break;
              case "COMBINATIONS":
                instance.combination_list = data[key];
                break;
              case "FEATURES":
                instance.feature_list = data[key];
            }
            df.resolve();
          },
          error: function (data) {
            df.reject();
          },
        })
      ),
      df.promise()
    );
  }
  function fireLoadEvent(status) {
    switch (status) {
      case "loadComplete":
        $(instance).trigger("loadComplete");
        break;
      case "loadFailed":
        $(instance).trigger("loadFailed");
    }
  }
  function getValidItemInSameGroup(invalidArr, checkItemGroupItems) {
    for (var i = 0; i < checkItemGroupItems.length; i++) {
      for (var isMatchId = !1, j = 0; j < invalidArr.length; j++) {
        new RegExp("\\b" + invalidArr[j] + "\\b").test(
          checkItemGroupItems[i].item_id
        ) && (isMatchId = !0);
      }
      if (!isMatchId) return checkItemGroupItems[i].item_id;
    }
  }
  function ConfigCore() {
    return (
      instance ||
      (((instance = this).grade_list = ""),
      (this.item_list = ""),
      (this.materials_list = ""),
      (this.combination_list = ""),
      (this.feature_list = ""),
      instance)
    );
  }
  return (
    (ConfigCore.getInstance = function () {
      return (instance = instance || new ConfigCore());
    }),
    (ConfigCore.prototype.loadSetting = function (data) {
      if (loaders) {
        for (var loadersLength = loaders.length, i = 0; i < loadersLength; i++)
          4 != loaders[i].readyState && loaders[i].abort();
        loaders = [];
      }
      var loadMethod,
        loadMethods = [];
      if ("string" == typeof data)
        (loadMethod = load(data)), loadMethods.push(loadMethod);
      else
        for (var file in data.files)
          data.files.hasOwnProperty(file) &&
            ((loadMethod = load(
              instance.grade_list.jsonDirPath + data.files[file]
            )),
            loadMethods.push(loadMethod));
      $.when
        .apply($, loadMethods)
        .done(function () {
          fireLoadEvent("loadComplete");
        })
        .fail(function () {
          fireLoadEvent("loadFailed");
        });
    }),
    (ConfigCore.prototype.validate = function (items) {
      var validatedItems = (function validateWithCombination(
          items,
          combination
        ) {
          "" != combination &&
            null != combination &&
            (this.validateCombination = combination);
          for (var i = 0; i < items.length; i++) {
            var item = items[i];
            if (
              "" != item &&
              "null" != item &&
              "" != this.validateCombination[item] &&
              null != this.validateCombination[item]
            ) {
              for (
                var str = items.join(","),
                  check = this.validateCombination[item],
                  invalid_items = check.invalid,
                  k = 0;
                k < invalid_items.length;
                k++
              ) {
                var invalidRegExp = new RegExp(
                    "\\b" + invalid_items[k] + "\\b"
                  ),
                  invalidRegExpMatch = str.match(invalidRegExp);
                  if (invalidRegExpMatch) {
                  var checkItemGroup = invalidRegExpMatch[0].split("_")[0];
                  str =
                    "radio" !=
                    (checkItemGroup = jsonPath(
                      instance.item_list,
                      "$.[?(@.group_id =='" + checkItemGroup + "')]"
                    )[0]).type
                      ? str.replace(
                          invalidRegExp,
                          invalidRegExpMatch[0] + NOT_SELECTED_ID_STR
                        )
                      : str.replace(
                          invalidRegExp,
                          getValidItemInSameGroup(
                            invalid_items,
                            checkItemGroup.items
                          )
                        );
                }
                str =
                  "," == str.charAt(0)
                    ? str.replace(",", "")
                    : str.replace(",,", ",");
              }
              for (
                var valid_items = check.valid, m = 0;
                m < valid_items.length;
                m++
              )
                new RegExp("\\b" + valid_items[m] + "\\b").test(str) ||
                  (str += "," + valid_items[m]),
                  (str =
                    "," == str.charAt(0)
                      ? str.replace(",", "")
                      : str.replace(",,", ","));
              if (items.join(",") != str) {
                items = validateWithCombination(
                  (items = str.split(",")),
                  combination
                );
                break;
              }
            }
          }
          return currentSelectItems.join(","), items.join(","), items;
        })((currentSelectItems = items), this.combination_list),
        disabledItems = (function (items) {
          for (var disabledItems = new Array(), i = 0; i < items.length; i++) {
            var item = items[i];
            if (
              "" != item &&
              "null" != item &&
              "" != this.validateCombination[item] &&
              null != this.validateCombination[item]
            ) {
              var invalid_items = this.validateCombination[item].invalid;
              $(invalid_items).each(function (i, elem) {
                var checkRegExp = new RegExp("\\b" + elem + "\\b"),
                  searchStr = disabledItems.join(",");
                checkRegExp.test(searchStr) || disabledItems.push(elem);
              });
            }
          }
          return disabledItems;
        })(validatedItems),
        autoChangeItems = (function (oldItems, newItems) {
          for (var autoChangeItems = {}, i = 0; i < newItems.length; i++) {
            var newItem = newItems[i],
              checkRegExp = new RegExp("\\b" + newItem + "\\b"),
              searchStr = oldItems.join(",");
            if (-1 == searchStr.search(checkRegExp)) {
              var oldItem,
                checkItemGroup = newItem.split("_")[0];
              if (
                "radio" !=
                (checkItemGroup = jsonPath(
                  instance.item_list,
                  "$.[?(@.group_id =='" + checkItemGroup + "')]"
                )[0]).type
              ) {
                var checkItemRegExp = new RegExp(NOT_SELECTED_ID_STR + "$");
                (checkItemRegExp = checkItemRegExp.test(newItem)
                  ? new RegExp(
                      "\\b" + newItem.replace(checkItemRegExp, "") + "\\b"
                    )
                  : new RegExp("\\b" + newItem + NOT_SELECTED_ID_STR + "\\b")),
                  (searchStr = oldItems.join(",")),
                  (autoChangeItems[
                    (oldItem = checkItemRegExp.exec(searchStr))
                  ] = newItem);
              } else
                for (var j = 0; j < oldItems.length; j++)
                  if (
                    ((oldItem = oldItems[j]),
                    (checkRegExp = new RegExp("\\b" + oldItem + "\\b")),
                    (searchStr = jsonPath(
                      checkItemGroup.items,
                      "$..item_id"
                    ).join(",")),
                    checkRegExp.test(searchStr))
                  ) {
                    autoChangeItems[oldItem] = newItem;
                    break;
                  }
            }
          }
          return autoChangeItems;
        })(items, validatedItems);
      return {
        selectItems: (currentSelectItems = validatedItems),
        disabledItems: disabledItems,
        autoChangeItems: autoChangeItems,
      };
    }),
    (ConfigCore.prototype.getDisplayMaterials = function (display, items) {
      for (var materials = new Array(), m = 0; m < display.length; m++) {
        for (var ok = !1, n = 0; n < display[m].items.length; n++) {
          var checkStr = "\\b" + display[m].items[n] + "\\b",
            checkRegExp = new RegExp(checkStr);
          if (((checkStr = items.join(",")), !checkRegExp.test(checkStr))) {
            ok = !1;
            break;
          }
          ok = !0;
        }
        ok &&
          materials.push({
            material: display[m].material,
            layer: display[m].layer,
          });
      }
      return materials;
    }),
    ConfigCore
  );
})();
