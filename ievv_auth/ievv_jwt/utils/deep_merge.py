def merge_dicts(dict1, dict2):
    result = dict(dict1)
    for key in dict2:
        if key in result:
            result[key] = deep_merge(result[key], dict2[key])
        else:
            result[key] = dict2[key]
    return result


def merge_lists(list1, list2):
    result = list(list1)
    for item in list2:
        if item not in result:
            result.append(item)
    return result


def merge_tuple(tuple1, tuple2):
    return tuple(merge_lists(tuple1, tuple2))


def deep_merge(object1, object2):
    if type(object1) != type(object2) and not (not object1 and object2 or not object2 and object1):
        raise ValueError('Merged objects must be of the same type. object1: {!r}, object2: {!r}'.format(object1, object2))
    if isinstance(object1, dict):
        return merge_dicts(object1, object2)
    elif isinstance(object1, tuple):
        return merge_tuple(object1, object2)
    elif isinstance(object1, list):
        return merge_lists(object1, object2)
    else:
        return object2
