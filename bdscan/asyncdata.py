import aiohttp
import asyncio
from bdscan import globals
# from bdscan import utils


def get_data_async(dirdeps, bd, trustcert):
    return asyncio.run(async_main(dirdeps, bd, trustcert))


async def async_main(compidlist, bd, trustcert):
    token = bd.session.auth.bearer_token

    # Get compids for components
    async with aiohttp.ClientSession() as session:
        compdata_tasks = []

        for compid in compidlist.compids:
            compdata_task = asyncio.ensure_future(async_get_compdata(session, bd.base_url, compid, token, trustcert))
            compdata_tasks.append(compdata_task)

        print('BD-Scan-Action: Getting componentid data ... ')
        # print(f'compidlist: {compidlist}')
        all_compdata = dict(await asyncio.gather(*compdata_tasks))
        await asyncio.sleep(0.25)
        globals.printdebug(f'got {len(all_compdata.keys())} all_compdata')
        for compid in all_compdata.keys():
            compidlist.set_data_in_comp(compid, 'compdata', all_compdata[compid])

    # Get upgradeguidance and lists of allversions
    async with aiohttp.ClientSession() as session:
        upgradeguidance_tasks = []
        versions_tasks = []

        for compid in compidlist.compids:
            # print(f"DEBUG: Get upgrade data for compid={compid} all_compdata={all_compdata}")
            upgradeguidance_task = asyncio.ensure_future(async_get_guidance(session, compid, all_compdata, token,
                                                                            trustcert))
            upgradeguidance_tasks.append(upgradeguidance_task)

            versions_task = asyncio.ensure_future(async_get_versions(session, compid, all_compdata, token, trustcert))
            versions_tasks.append(versions_task)

        print('BD-Scan-Action: Getting component versions & upgrade guidance data ... ')
        all_upgradeguidance = dict(await asyncio.gather(*upgradeguidance_tasks))
        all_versions = dict(await asyncio.gather(*versions_tasks))
        await asyncio.sleep(0.25)
        for compid in all_upgradeguidance.keys():
            compidlist.set_data_in_comp(compid, 'upgradeguidance', all_upgradeguidance[compid])
        for compid in all_versions.keys():
            compidlist.set_data_in_comp(compid, 'versions', all_versions[compid])

        globals.printdebug(f'got {len(all_upgradeguidance.keys())} all_upgradeguidances = {all_upgradeguidance}')
        globals.printdebug(f'got {len(all_versions.keys())} all_versions')

    # Now get origin data - need to work out the subset of valid future versions to reduce requests
    async with aiohttp.ClientSession() as session:
        origins_tasks = []

        # reduced_version_list = {}
        for comp in compidlist.components:
            # c_org, c_name, c_ver = comp.parse_compid(comp.compid)
            # tempcompid = comp.compid.replace(':', '|').replace('/', '|')
            # arr = tempcompid.split('|')
            if len(comp.versions) == 0:
                continue
            # curr_ver = comp.check_version_is_release(c_ver)
            # short_guidance_ver = comp.check_version_is_release(comp.upgradeguidance[0])
            # reduced_version_list[compid] = []

            # If component does not support upgrades, skip
            if not comp.supports_direct_upgrades():
                continue

            # for vers, versurl in all_versions[compid][::-1]:
            for vers, versurl in comp.versions[::-1]:
                if not comp.is_goodfutureversion(vers):
                    continue
                comp.set_data('goodfutureversions', [vers, versurl])

                origins_task = asyncio.ensure_future(async_get_origins(session, comp.compid,
                                                                       vers, versurl, token, trustcert))
                origins_tasks.append(origins_task)

        print('BD-Scan-Action: Getting version origin data ... ')
        all_origins = dict(await asyncio.gather(*origins_tasks))
        await asyncio.sleep(0.25)
        for origin in all_origins.keys():
            arr = origin.split('|')
            compidlist.add_origins_to_comp(arr[0], arr[1], all_origins[origin])
        globals.printdebug(f'got {len(all_origins.keys())} all_origins')

    # return all_upgradeguidances, all_versions
    # return all_upgradeguidances, reduced_version_list, all_origins
    return


async def async_get_compdata(session, baseurl, compid, token, trustcert):
    # if 'componentIdentifier' not in comp:
    #     return None, None
    #
    if trustcert:
        ssl = False
    else:
        ssl = True

    headers = {
        'accept': "application/vnd.blackducksoftware.component-detail-4+json",
        'Authorization': f'Bearer {token}',
    }

    params = {
        # 'q': [comp['componentIdentifier']],
        'q': [compid],
    }
    # search_results = bd.get_items('/api/components', params=params)
    async with session.get(baseurl + '/api/components', headers=headers, params=params, ssl=ssl) as resp:
        found_comps = await resp.json()

    # print('----')
    # print(baseurl + '/api/components?q=' + compid)
    # print(found_comps)
    if 'items' not in found_comps or len(found_comps['items']) != 1:
        return None, None

    found = found_comps['items'][0]

    # return comp['componentIdentifier'], [found['variant'] + '/upgrade-guidance', found['component'] + '/versions']
    return compid, [found['variant'] + '/upgrade-guidance', found['component'] + '/versions']


async def async_get_versions(session, compid, compdata, token, trustcert):
    if compid in compdata:
        gurl = compdata[compid][1]
    else:
        return None, None

    if trustcert:
        ssl = False
    else:
        ssl = True

    # print(f'GETTING VERSION: {compid}')
    headers = {
        'accept': "application/vnd.blackducksoftware.component-detail-4+json",
        'Authorization': f'Bearer {token}',
    }

    params = {
        'limit': 1000,
        'sort': 'releasedOn',
    }

    async with session.get(gurl, headers=headers, params=params, ssl=ssl) as resp:
        res = await resp.json()

    versions_list = []
    for version in res['items']:
        item = [version['versionName'], version['_meta']['href']]
        versions_list.append(item)

    # print(compid)
    # print(versions_list)

    return compid, versions_list


async def async_get_guidance(session, compid, compdata, token, trustcert):
    if trustcert:
        ssl = False
    else:
        ssl = True

    headers = {
        'accept': "application/vnd.blackducksoftware.component-detail-5+json",
        'Authorization': f'Bearer {token}',
    }
    # if 'componentIdentifier' in comp and comp['componentIdentifier'] in compdata:
    #     gurl = compdata[comp['componentIdentifier']][0]
    # else:
    #     return None, None
    if compid in compdata.keys():
        gurl = compdata[compid][0]
    else:
        return None, None

    async with session.get(gurl, headers=headers, ssl=ssl) as resp:
        component_upgrade_data = await resp.json()

    globals.printdebug(component_upgrade_data)
    if "longTerm" in component_upgrade_data.keys():
        long_term = component_upgrade_data['longTerm']['versionName']
    else:
        long_term = ''

    if "shortTerm" in component_upgrade_data.keys():
        short_term = component_upgrade_data['shortTerm']['versionName']
    else:
        short_term = ''
    # print(f"Comp = {comp['componentName']}/{comp['versionName']} - Short = {shortTerm} Long = {longTerm}")

    if short_term == long_term:
        long_term = ''
    return compid, [short_term, long_term]


async def async_get_origins(session, compid, ver, verurl, token, trustcert):
    # globals.printdebug(f"{compid}: {ver} - {verurl}")
    if trustcert:
        ssl = False
    else:
        ssl = True

    headers = {
        'accept': "application/vnd.blackducksoftware.component-detail-5+json",
        'Authorization': f'Bearer {token}',
    }

    params = {
        'limit': 1000,
    }

    # if 'componentIdentifier' in comp and comp['componentIdentifier'] in compdata:
    #     gurl = compdata[comp['componentIdentifier']][0]
    # else:
    #     return None, None

    async with session.get(verurl + '/origins', headers=headers, params=params, ssl=ssl) as resp:
        origins = await resp.json()

    # print('get_origins:')
    # print(len(origins))

    return f"{compid}|{ver}", origins['items']
